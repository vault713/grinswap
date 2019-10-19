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

use super::client::Output;
use crate::swap::message::SecondaryUpdate;
use crate::swap::ser::*;
use crate::swap::types::{Network, SecondaryData};
use crate::swap::{ErrorKind, Keychain};
use bitcoin::blockdata::opcodes::{all::*, OP_FALSE};
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::Encodable;
use bitcoin::network::constants::Network as BtcNetwork;
use bitcoin::{Address, Script, Transaction, TxIn, TxOut, VarInt};
use bitcoin_hashes::sha256d;
use byteorder::{ByteOrder, LittleEndian};
use chrono::Utc;
use grin_keychain::{Identifier, SwitchCommitmentType};
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::{Message, Secp256k1, Signature};
use std::io::Cursor;
use std::ops::Deref;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcRedeemTx {
	pub txid: sha256d::Hash,
	#[serde(serialize_with = "bytes_to_hex", deserialize_with = "bytes_from_hex")]
	pub tx: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcData {
	pub lock_time: u32,
	/// Key owned by seller
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub cosign: PublicKey,
	/// Key owned by buyer
	#[serde(
		serialize_with = "option_pubkey_to_hex",
		deserialize_with = "option_pubkey_from_hex"
	)]
	pub refund: Option<PublicKey>,
	pub confirmed_outputs: Vec<Output>,
	pub locked: bool,
	pub redeem_tx: Option<BtcRedeemTx>,
	pub redeem_confirmations: Option<u64>,
	#[serde(skip)]
	pub script: Option<Script>,
}

impl BtcData {
	pub(crate) fn new<K>(
		keychain: &K,
		context: &BtcSellerContext,
		duration: Duration,
	) -> Result<Self, ErrorKind>
	where
		K: Keychain,
	{
		let lock_time = if crate::swap::is_test_mode() {
			1567718553
		} else {
			Utc::now().timestamp() as u64 + duration.as_secs()
		};
		assert!(lock_time > 0 && lock_time < std::u32::MAX as u64);

		let cosign = PublicKey::from_secret_key(
			keychain.secp(),
			&keychain.derive_key(0, &context.cosign, &SwitchCommitmentType::None)?,
		)?;

		Ok(Self {
			lock_time: lock_time as u32,
			cosign,
			refund: None,
			confirmed_outputs: Vec::new(),
			locked: false,
			redeem_tx: None,
			redeem_confirmations: None,
			script: None,
		})
	}

	pub(crate) fn from_offer<K>(
		keychain: &K,
		offer: BtcOfferUpdate,
		context: &BtcBuyerContext,
	) -> Result<Self, ErrorKind>
	where
		K: Keychain,
	{
		let key = keychain.derive_key(0, &context.refund, &SwitchCommitmentType::None)?;

		Ok(Self {
			lock_time: offer.lock_time,
			cosign: offer.cosign,
			refund: Some(PublicKey::from_secret_key(keychain.secp(), &key)?),
			confirmed_outputs: Vec::new(),
			locked: false,
			redeem_tx: None,
			redeem_confirmations: None,
			script: None,
		})
	}

	pub(crate) fn accepted_offer(
		&mut self,
		accepted_offer: BtcAcceptOfferUpdate,
	) -> Result<(), ErrorKind> {
		self.refund = Some(accepted_offer.refund);
		Ok(())
	}

	pub(crate) fn wrap(self) -> SecondaryData {
		SecondaryData::Btc(self)
	}

	/// Generate the multisig-with-timelocked-refund script
	pub fn script(&mut self, secp: &Secp256k1, redeem: &PublicKey) -> Result<(), ErrorKind> {
		if self.script.is_none() {
			let mut time = [0; 4];
			LittleEndian::write_u32(&mut time, self.lock_time);

			let refund = self
				.refund
				.ok_or(ErrorKind::SecondaryDataIncomplete)?
				.serialize_vec(secp, true);
			let cosign = self.cosign.serialize_vec(secp, true);
			let redeem = redeem.serialize_vec(secp, true);

			let builder = Builder::new()
				.push_opcode(OP_IF) // Refund path
				.push_slice(&time)
				.push_opcode(OP_CLTV) // Check transaction lock time
				.push_opcode(OP_DROP)
				.push_slice(refund.as_slice())
				.push_opcode(OP_CHECKSIG) // Check signature
				.push_opcode(OP_ELSE) // Redeem path
				.push_opcode(OP_PUSHNUM_2)
				.push_slice(cosign.as_slice())
				.push_slice(redeem.as_slice())
				.push_opcode(OP_PUSHNUM_2)
				.push_opcode(OP_CHECKMULTISIG) // Check 2-of-2 multisig
				.push_opcode(OP_ENDIF);

			self.script = Some(builder.into_script());
		}

		Ok(())
	}

	/// Generate the P2SH address for the script
	pub fn address(&self, network: Network) -> Result<Address, ErrorKind> {
		let address = Address::p2sh(
			self.script
				.as_ref()
				.ok_or(ErrorKind::Generic("Missing script".into()))?,
			btc_network(network),
		);
		Ok(address)
	}

	pub(crate) fn redeem_tx(
		&mut self,
		secp: &Secp256k1,
		redeem_address: &Address,
		fee_sat_per_byte: u64,
		cosign_secret: &SecretKey,
		redeem_secret: &SecretKey,
	) -> Result<(Transaction, usize, usize), ErrorKind> {
		let input_script = self
			.script
			.as_ref()
			.ok_or(ErrorKind::Generic("Missing script".into()))?;

		// Input(s)
		let mut input = Vec::with_capacity(self.confirmed_outputs.len());
		let mut total_amount = 0;
		for o in &self.confirmed_outputs {
			total_amount += o.value;
			input.push(TxIn {
				previous_output: o.out_point.clone(),
				script_sig: Script::new(),
				sequence: 0xFFFFFFFF,
				witness: Vec::new(),
			});
		}

		// Output
		let mut output = Vec::with_capacity(1);
		output.push(TxOut {
			value: total_amount, // Will be overwritten later
			script_pubkey: redeem_address.script_pubkey(),
		});

		let mut tx = Transaction {
			version: 2,
			lock_time: 0,
			input,
			output,
		};

		// Calculate tx size
		let mut script_sig_size = input_script.len();
		script_sig_size += VarInt(script_sig_size as u64).len();
		script_sig_size += 2 * (1 + 72 + 1); // Signatures
		script_sig_size += 2; // Opcodes
		let tx_size = tx.get_weight() / 4 + script_sig_size * tx.input.len();

		// Subtract fee from output
		tx.output[0].value = total_amount.saturating_sub(tx_size as u64 * fee_sat_per_byte);

		// Sign for inputs
		for idx in 0..tx.input.len() {
			let hash = tx.signature_hash(idx, &input_script, 0x01);
			let msg = Message::from_slice(hash.deref())?;

			tx.input.get_mut(idx).unwrap().script_sig = self.redeem_script_sig(
				secp,
				&secp.sign(&msg, cosign_secret)?,
				&secp.sign(&msg, redeem_secret)?,
			)?;
		}

		let mut cursor = Cursor::new(Vec::with_capacity(tx_size));
		let actual_size = tx
			.consensus_encode(&mut cursor)
			.map_err(|_| ErrorKind::Generic("Unable to encode redeem tx".into()))?;

		self.redeem_tx = Some(BtcRedeemTx {
			txid: tx.txid(),
			tx: cursor.into_inner(),
		});

		Ok((tx, tx_size, actual_size))
	}

	fn redeem_script_sig(
		&self,
		secp: &Secp256k1,
		cosign_signature: &Signature,
		redeem_signature: &Signature,
	) -> Result<Script, ErrorKind> {
		let mut cosign_ser = cosign_signature.serialize_der(secp);
		cosign_ser.push(0x01); // SIGHASH_ALL

		let mut redeem_ser = redeem_signature.serialize_der(secp);
		redeem_ser.push(0x01); // SIGHASH_ALL

		let script_sig = Builder::new()
			.push_opcode(OP_FALSE) // Bitcoin multisig bug
			.push_slice(&cosign_ser)
			.push_slice(&redeem_ser)
			.push_opcode(OP_FALSE) // Choose redeem path in original script
			.push_slice(
				&self
					.script
					.as_ref()
					.ok_or(ErrorKind::Generic("Missing script".into()))?
					.to_bytes(),
			)
			.into_script();

		Ok(script_sig)
	}

	pub(crate) fn offer_update(&self) -> BtcUpdate {
		BtcUpdate::Offer(BtcOfferUpdate {
			lock_time: self.lock_time,
			cosign: self.cosign.clone(),
		})
	}

	pub(crate) fn accept_offer_update(&self) -> Result<BtcUpdate, ErrorKind> {
		Ok(BtcUpdate::AcceptOffer(BtcAcceptOfferUpdate {
			refund: self.refund.ok_or(ErrorKind::UnexpectedMessageType)?.clone(),
		}))
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcSellerContext {
	pub cosign: Identifier,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcBuyerContext {
	pub refund: Identifier,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BtcUpdate {
	Offer(BtcOfferUpdate),
	AcceptOffer(BtcAcceptOfferUpdate),
}

impl BtcUpdate {
	pub fn unwrap_offer(self) -> Result<BtcOfferUpdate, ErrorKind> {
		match self {
			BtcUpdate::Offer(u) => Ok(u),
			_ => Err(ErrorKind::UnexpectedMessageType),
		}
	}

	pub fn unwrap_accept_offer(self) -> Result<BtcAcceptOfferUpdate, ErrorKind> {
		match self {
			BtcUpdate::AcceptOffer(u) => Ok(u),
			_ => Err(ErrorKind::UnexpectedMessageType),
		}
	}

	pub fn wrap(self) -> SecondaryUpdate {
		SecondaryUpdate::BTC(self)
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcOfferUpdate {
	pub lock_time: u32,
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub cosign: PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcAcceptOfferUpdate {
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub refund: PublicKey,
}

fn btc_network(network: Network) -> BtcNetwork {
	match network {
		Network::Floonet => BtcNetwork::Testnet,
		Network::Mainnet => BtcNetwork::Bitcoin,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::util::address::Payload;
	use bitcoin::util::key::PublicKey as BTCPublicKey;
	use bitcoin::OutPoint;
	use bitcoin_hashes::{hash160, Hash};
	use grin_util::from_hex;
	use grin_util::secp::key::PublicKey;
	use grin_util::secp::{ContextFlag, Secp256k1};
	use rand::{thread_rng, Rng, RngCore};
	use std::collections::HashMap;

	#[test]
	/// Test vector from the PoC
	fn test_lock_script() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		let mut data = BtcData {
			lock_time: 1541355813,
			cosign: PublicKey::from_slice(
				&secp,
				&from_hex(
					"02b4e59070d367a364a31981a71fc5ab6c5034d0e279eecec19287f3c95db84aef".into(),
				)
				.unwrap(),
			)
			.unwrap(),
			refund: Some(
				PublicKey::from_slice(
					&secp,
					&from_hex(
						"022fd8c0455bede249ad3b9a9fb8159829e8cfb2c360863896e5309ea133d122f2".into(),
					)
					.unwrap(),
				)
				.unwrap(),
			),
			confirmed_outputs: Vec::new(),
			locked: false,
			redeem_tx: None,
			redeem_confirmations: None,
			script: None,
		};

		data.script(
			&secp,
			&PublicKey::from_slice(
				&secp,
				&from_hex(
					"03cf15041579b5fb7accbac2997fb2f3e1001e9a522a19c83ceabe5ae51a596c7c".into(),
				)
				.unwrap(),
			)
			.unwrap(),
		)
		.unwrap();
		let script_ref = from_hex("63042539df5bb17521022fd8c0455bede249ad3b9a9fb8159829e8cfb2c360863896e5309ea133d122f2ac67522102b4e59070d367a364a31981a71fc5ab6c5034d0e279eecec19287f3c95db84aef2103cf15041579b5fb7accbac2997fb2f3e1001e9a522a19c83ceabe5ae51a596c7c52ae68".into()).unwrap();
		assert_eq!(data.script.clone().unwrap().to_bytes(), script_ref);

		assert_eq!(
			format!("{}", data.address(Network::Floonet).unwrap()),
			String::from("2NEwEAG9VyFYt2sjLpuHrU4Abb7nGJfc7PR")
		);
	}

	#[test]
	fn test_redeem_script() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let rng = &mut thread_rng();
		let network = Network::Floonet;

		let cosign = SecretKey::new(&secp, rng);
		let refund = SecretKey::new(&secp, rng);
		let redeem = SecretKey::new(&secp, rng);

		let mut data = BtcData {
			lock_time: Utc::now().timestamp() as u32,
			cosign: PublicKey::from_secret_key(&secp, &cosign).unwrap(),
			refund: Some(PublicKey::from_secret_key(&secp, &refund).unwrap()),
			confirmed_outputs: Vec::new(),
			locked: false,
			redeem_tx: None,
			redeem_confirmations: None,
			script: None,
		};
		data.script(&secp, &PublicKey::from_secret_key(&secp, &redeem).unwrap())
			.unwrap();
		let lock_address = data.address(network).unwrap();
		let lock_script_pubkey = lock_address.script_pubkey();

		// Create a bunch of funding transactions
		let count = rng.gen_range(3, 7);
		let mut funding_txs = HashMap::with_capacity(count);
		for i in 0..count {
			let value = (i as u64 + 1) * 1_000_000;

			// Generate a bunch of trash P2PKH and P2SH outputs
			let vout = rng.gen_range(0usize, 5);
			let mut output = Vec::with_capacity(vout + 1);
			for _ in 0..vout {
				let mut hash: Vec<u8> = vec![0; 20];
				rng.fill_bytes(&mut hash);
				let hash = hash160::Hash::from_slice(&hash).unwrap();
				let payload = if rng.gen_bool(0.5) {
					Payload::PubkeyHash(hash)
				} else {
					Payload::ScriptHash(hash)
				};
				let script_pubkey = payload.script_pubkey();
				output.push(TxOut {
					value: rng.gen(),
					script_pubkey,
				});
			}
			output.push(TxOut {
				value,
				script_pubkey: lock_script_pubkey.clone(),
			});

			let tx = Transaction {
				version: 2,
				lock_time: data.lock_time - 1,
				input: vec![],
				output,
			};

			let txid = tx.txid();
			data.confirmed_outputs.push(Output {
				out_point: OutPoint {
					txid: txid.clone(),
					vout: vout as u32,
				},
				value,
				height: 1,
			});
			funding_txs.insert(tx.txid(), tx);
		}

		let redeem_address = Address::p2pkh(
			&BTCPublicKey {
				compressed: true,
				key: PublicKey::from_secret_key(&secp, &SecretKey::new(&secp, rng)).unwrap(),
			},
			btc_network(network),
		);

		// Generate redeem transaction
		let (tx, est_size, actual_size) = data
			.redeem_tx(&secp, &redeem_address, 10, &cosign, &redeem)
			.unwrap();
		let diff = (est_size as i64 - actual_size as i64).abs() as usize;
		assert!(diff <= count); // Our size estimation should be very close to the real size

		// Moment of truth: our redeem tx should be valid
		tx.verify(&funding_txs).unwrap();
	}
}
