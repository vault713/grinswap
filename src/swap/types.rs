// Copyright 2019 The vault713 Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::bitcoin::{BtcBuyerContext, BtcData, BtcSellerContext};
use super::ser::*;
use super::ErrorKind;
use grin_core::global::ChainTypes;
use grin_core::ser;
use grin_keychain::Identifier;
use grin_util::secp::key::SecretKey;
use std::convert::TryFrom;
use std::fmt;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
	Floonet,
	Mainnet,
}

impl Network {
	pub fn from_chain_type(chain_type: ChainTypes) -> Result<Self, ErrorKind> {
		match chain_type {
			ChainTypes::Floonet => Ok(Network::Floonet),
			ChainTypes::Mainnet => Ok(Network::Mainnet),
			_ => Err(ErrorKind::UnexpectedNetwork),
		}
	}

	pub fn to_chain_type(&self) -> ChainTypes {
		match self {
			Network::Floonet => ChainTypes::Floonet,
			Network::Mainnet => ChainTypes::Mainnet,
		}
	}
}

impl PartialEq<ChainTypes> for Network {
	fn eq(&self, other: &ChainTypes) -> bool {
		self.to_chain_type() == *other
	}
}

impl PartialEq<Network> for ChainTypes {
	fn eq(&self, other: &Network) -> bool {
		*self == other.to_chain_type()
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Role {
	Seller(String, u64),
	Buyer,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
	Created,
	Offered,
	Accepted,
	Locked,
	InitRedeem,
	Redeem,
	RedeemSecondary,
	Completed,
	Refunded,
	Cancelled,
}

impl fmt::Display for Status {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let disp = match &self {
			Status::Created => "created",
			Status::Offered => "offered",
			Status::Accepted => "accepted",
			Status::Locked => "locked",
			Status::InitRedeem => "init redeem",
			Status::Redeem => "buyer redeem",
			Status::RedeemSecondary => "seller redeem",
			Status::Completed => "completed",
			Status::Refunded => "refunded",
			Status::Cancelled => "cancelled",
		};
		write!(f, "{}", disp)
	}
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Currency {
	Btc,
}

impl Currency {
	pub fn exponent(&self) -> usize {
		match self {
			Currency::Btc => 8,
		}
	}

	pub fn amount_to_hr_string(&self, amount: u64, truncate: bool) -> String {
		let exp = self.exponent();
		let a = format!("{}", amount);
		let len = a.len();
		let pos = len.saturating_sub(exp);
		let (characteristic, mantissa_prefix) = if pos > 0 {
			(&a[..(len - exp)], String::new())
		} else {
			("0", "0".repeat(exp - len))
		};
		let mut mantissa = &a[pos..];
		if truncate {
			let nzeroes = mantissa.chars().rev().take_while(|c| c == &'0').count();
			mantissa = &a[pos..(a.len().saturating_sub(nzeroes))];
			if mantissa.len() == 0 {
				mantissa = "0";
			}
		}
		format!("{}.{}{}", characteristic, mantissa_prefix, mantissa)
	}

	pub fn amount_from_hr_string(&self, hr: &str) -> Result<u64, ErrorKind> {
		if hr.find(",").is_some() {
			return Err(ErrorKind::InvalidAmountString);
		}

		let exp = self.exponent();

		let (characteristic, mantissa) = match hr.find(".") {
			Some(pos) => {
				let (c, m) = hr.split_at(pos);
				(parse_characteristic(c)?, parse_mantissa(&m[1..], exp)?)
			}
			None => (parse_characteristic(hr)?, 0),
		};

		let amount = characteristic * 10u64.pow(exp as u32) + mantissa;
		if amount == 0 {
			return Err(ErrorKind::InvalidAmountString);
		}

		Ok(amount)
	}
}

impl fmt::Display for Currency {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let disp = match &self {
			Currency::Btc => "BTC",
		};
		write!(f, "{}", disp)
	}
}

impl TryFrom<&str> for Currency {
	type Error = ErrorKind;

	fn try_from(value: &str) -> Result<Self, Self::Error> {
		match value.to_lowercase().as_str() {
			"btc" => Ok(Currency::Btc),
			_ => Err(ErrorKind::InvalidCurrency),
		}
	}
}

fn parse_characteristic(characteristic: &str) -> Result<u64, ErrorKind> {
	if characteristic.len() == 0 {
		return Ok(0);
	}

	characteristic
		.parse()
		.map_err(|_| ErrorKind::InvalidAmountString)
}

fn parse_mantissa(mantissa: &str, exp: usize) -> Result<u64, ErrorKind> {
	let mut m = format!("{:0<w$}", mantissa, w = exp);
	m.truncate(exp);

	let m = m.trim_start_matches("0");
	if m.len() == 0 {
		return Ok(0);
	}

	m.parse().map_err(|_| ErrorKind::InvalidAmountString)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecondaryData {
	Empty,
	Btc(BtcData),
}

impl SecondaryData {
	pub fn unwrap_btc(&self) -> Result<&BtcData, ErrorKind> {
		match self {
			SecondaryData::Btc(d) => Ok(d),
			_ => Err(ErrorKind::UnexpectedCoinType),
		}
	}

	pub fn unwrap_btc_mut(&mut self) -> Result<&mut BtcData, ErrorKind> {
		match self {
			SecondaryData::Btc(d) => Ok(d),
			_ => Err(ErrorKind::UnexpectedCoinType),
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Context {
	pub multisig_key: Identifier,
	#[serde(serialize_with = "seckey_to_hex", deserialize_with = "seckey_from_hex")]
	pub multisig_nonce: SecretKey,
	#[serde(serialize_with = "seckey_to_hex", deserialize_with = "seckey_from_hex")]
	pub lock_nonce: SecretKey,
	#[serde(serialize_with = "seckey_to_hex", deserialize_with = "seckey_from_hex")]
	pub refund_nonce: SecretKey,
	#[serde(serialize_with = "seckey_to_hex", deserialize_with = "seckey_from_hex")]
	pub redeem_nonce: SecretKey,
	pub role_context: RoleContext,
}

impl Context {
	pub fn unwrap_seller(&self) -> Result<&SellerContext, ErrorKind> {
		match &self.role_context {
			RoleContext::Seller(c) => Ok(c),
			RoleContext::Buyer(_) => Err(ErrorKind::UnexpectedRole),
		}
	}

	pub fn unwrap_buyer(&self) -> Result<&BuyerContext, ErrorKind> {
		match &self.role_context {
			RoleContext::Seller(_) => Err(ErrorKind::UnexpectedRole),
			RoleContext::Buyer(c) => Ok(c),
		}
	}
}

impl ser::Writeable for Context {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

impl ser::Readable for Context {
	fn read(reader: &mut dyn ser::Reader) -> Result<Context, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|_| ser::Error::CorruptedData)
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RoleContext {
	Seller(SellerContext),
	Buyer(BuyerContext),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SellerContext {
	pub inputs: Vec<(Identifier, u64)>,
	pub change_output: Identifier,
	pub refund_output: Identifier,
	pub secondary_context: SecondarySellerContext,
}

impl SellerContext {
	pub fn unwrap_btc(&self) -> Result<&BtcSellerContext, ErrorKind> {
		match &self.secondary_context {
			SecondarySellerContext::Btc(c) => Ok(c),
			//_ => Err(ErrorKind::UnexpectedCoinType),
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BuyerContext {
	pub output: Identifier,
	pub redeem: Identifier,
	pub secondary_context: SecondaryBuyerContext,
}

impl BuyerContext {
	pub fn unwrap_btc(&self) -> Result<&BtcBuyerContext, ErrorKind> {
		match &self.secondary_context {
			SecondaryBuyerContext::Btc(c) => Ok(c),
			//_ => Err(ErrorKind::UnexpectedCoinType),
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecondarySellerContext {
	Btc(BtcSellerContext),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecondaryBuyerContext {
	Btc(BtcBuyerContext),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Action {
	/// No further action required
	None,
	/// Send a message to the counterparty
	SendMessage(usize),
	/// Wait for a message from the counterparty
	ReceiveMessage,
	/// Publish a transaction to the network
	PublishTx,
	/// Publish a transaction to the network of the secondary currency
	PublishTxSecondary(Currency),
	/// Deposit secondary currency
	DepositSecondary {
		currency: Currency,
		amount: u64,
		address: String,
	},
	/// Wait for sufficient confirmations
	Confirmations { required: u64, actual: u64 },
	/// Wait for sufficient confirmations on the secondary currency
	ConfirmationsSecondary {
		currency: Currency,
		required: u64,
		actual: u64,
	},
	/// Wait for the Grin redeem tx to be mined
	ConfirmationRedeem,
	/// Wait for the secondary redeem tx to be mined
	ConfirmationRedeemSecondary(Currency, String),
	/// Complete swap
	Complete,
	/// Cancel swap
	Cancel,
	/// Execute refund
	Refund,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_amounts_to_hr() {
		let c = Currency::Btc;
		assert_eq!(&c.amount_to_hr_string(1, false), "0.00000001");
		assert_eq!(&c.amount_to_hr_string(100, false), "0.00000100");
		assert_eq!(&c.amount_to_hr_string(713, false), "0.00000713");
		assert_eq!(&c.amount_to_hr_string(100_000, false), "0.00100000");
		assert_eq!(&c.amount_to_hr_string(10_000_000, false), "0.10000000");
		assert_eq!(&c.amount_to_hr_string(12_345_678, false), "0.12345678");
		assert_eq!(&c.amount_to_hr_string(100_000_000, false), "1.00000000");
		assert_eq!(&c.amount_to_hr_string(100_200_300, false), "1.00200300");
		assert_eq!(&c.amount_to_hr_string(102_030_405, false), "1.02030405");
		assert_eq!(&c.amount_to_hr_string(110_000_000, false), "1.10000000");
		assert_eq!(&c.amount_to_hr_string(123_456_789, false), "1.23456789");
		assert_eq!(&c.amount_to_hr_string(1_000_000_000, false), "10.00000000");
		assert_eq!(&c.amount_to_hr_string(1_020_304_050, false), "10.20304050");
		assert_eq!(
			&c.amount_to_hr_string(10_000_000_000, false),
			"100.00000000"
		);
		assert_eq!(
			&c.amount_to_hr_string(10_000_000_001, false),
			"100.00000001"
		);
		assert_eq!(
			&c.amount_to_hr_string(10_000_000_010, false),
			"100.00000010"
		);
		assert_eq!(
			&c.amount_to_hr_string(10_000_000_100, false),
			"100.00000100"
		);

		assert_eq!(&c.amount_to_hr_string(1, true), "0.00000001");
		assert_eq!(&c.amount_to_hr_string(100, true), "0.000001");
		assert_eq!(&c.amount_to_hr_string(713, true), "0.00000713");
		assert_eq!(&c.amount_to_hr_string(100_000, true), "0.001");
		assert_eq!(&c.amount_to_hr_string(10_000_000, true), "0.1");
		assert_eq!(&c.amount_to_hr_string(12_345_678, true), "0.12345678");
		assert_eq!(&c.amount_to_hr_string(100_000_000, true), "1.0");
		assert_eq!(&c.amount_to_hr_string(100_200_300, true), "1.002003");
		assert_eq!(&c.amount_to_hr_string(102_030_405, true), "1.02030405");
		assert_eq!(&c.amount_to_hr_string(110_000_000, true), "1.1");
		assert_eq!(&c.amount_to_hr_string(123_456_789, true), "1.23456789");
		assert_eq!(&c.amount_to_hr_string(1_000_000_000, true), "10.0");
		assert_eq!(&c.amount_to_hr_string(1_020_304_050, true), "10.2030405");
		assert_eq!(&c.amount_to_hr_string(10_000_000_000, true), "100.0");
		assert_eq!(&c.amount_to_hr_string(10_000_000_001, true), "100.00000001");
		assert_eq!(&c.amount_to_hr_string(10_000_000_010, true), "100.0000001");
		assert_eq!(&c.amount_to_hr_string(10_000_000_100, true), "100.000001");
	}

	#[test]
	fn test_amounts_from_hr() {
		let c = Currency::Btc;
		assert!(c.amount_from_hr_string("").is_err());
		assert!(c.amount_from_hr_string(".").is_err());
		assert!(c.amount_from_hr_string("0").is_err());
		assert!(c.amount_from_hr_string("0.").is_err());
		assert!(c.amount_from_hr_string("0.0").is_err());
		assert!(c.amount_from_hr_string("0.000000001").is_err());
		assert_eq!(c.amount_from_hr_string("0.00000001").unwrap(), 1);
		assert_eq!(c.amount_from_hr_string(".00000001").unwrap(), 1);
		assert_eq!(c.amount_from_hr_string("0.00000713").unwrap(), 713);
		assert_eq!(c.amount_from_hr_string(".00000713").unwrap(), 713);
		assert_eq!(c.amount_from_hr_string("0.0001").unwrap(), 10_000);
		assert_eq!(c.amount_from_hr_string("0.1").unwrap(), 10_000_000);
		assert_eq!(c.amount_from_hr_string("0.10").unwrap(), 10_000_000);
		assert_eq!(c.amount_from_hr_string(".1").unwrap(), 10_000_000);
		assert_eq!(c.amount_from_hr_string(".10").unwrap(), 10_000_000);
		assert_eq!(c.amount_from_hr_string("0.123456789").unwrap(), 12_345_678);
		assert_eq!(c.amount_from_hr_string("1").unwrap(), 100_000_000);
		assert_eq!(c.amount_from_hr_string("1.").unwrap(), 100_000_000);
		assert_eq!(c.amount_from_hr_string("1.0").unwrap(), 100_000_000);
		assert_eq!(
			c.amount_from_hr_string("123456.789").unwrap(),
			12_345_678_900_000
		);
	}
}
