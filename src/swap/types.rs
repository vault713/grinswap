use super::bitcoin::{BTCBuyerContext, BTCData, BTCSellerContext};
use super::ser::*;
use super::ErrorKind;
use grin_core::global::ChainTypes;
use grin_core::ser;
use grin_keychain::Identifier;
use grin_util::secp::key::SecretKey;

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

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Currency {
	BTC,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecondaryData {
	Empty,
	BTC(BTCData),
}

impl SecondaryData {
	pub fn unwrap_btc(&self) -> Result<&BTCData, ErrorKind> {
		match self {
			SecondaryData::BTC(d) => Ok(d),
			_ => Err(ErrorKind::UnexpectedCoinType),
		}
	}

	pub fn unwrap_btc_mut(&mut self) -> Result<&mut BTCData, ErrorKind> {
		match self {
			SecondaryData::BTC(d) => Ok(d),
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
	pub fn unwrap_btc(&self) -> Result<&BTCSellerContext, ErrorKind> {
		match &self.secondary_context {
			SecondarySellerContext::BTC(c) => Ok(c),
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
	pub fn unwrap_btc(&self) -> Result<&BTCBuyerContext, ErrorKind> {
		match &self.secondary_context {
			SecondaryBuyerContext::BTC(c) => Ok(c),
			//_ => Err(ErrorKind::UnexpectedCoinType),
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecondarySellerContext {
	BTC(BTCSellerContext),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecondaryBuyerContext {
	BTC(BTCBuyerContext),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Action {
	/// No further action required
	None,
	/// Send a message to the counterparty
	SendMessage,
	/// Wait for a message from the counterparty
	ReceiveMessage,
	/// Publish a transaction to the network
	PublishTx,
	/// Publish a transaction to the network of the secondary currency
	PublishTxSecondary,
	/// Deposit secondary currency
	DepositSecondary { amount: u64, address: String },
	/// Wait for sufficient confirmations
	Confirmations { required: u64, actual: u64 },
	/// Wait for sufficient confirmations on the secondary currency
	ConfirmationsSecondary { required: u64, actual: u64 },
	/// Wait for the Grin redeem tx to be mined
	ConfirmationRedeem,
	/// Wait for the secondary redeem tx to be mined
	ConfirmationRedeemSecondary(String),
	/// Complete swap
	Complete,
	/// Cancel swap
	Cancel,
	/// Execute refund
	Refund,
}
