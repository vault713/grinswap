use super::message::*;
use super::multisig::{Builder as MultisigBuilder, Hashed};
use super::ser::*;
use super::types::*;
use super::{ErrorKind, Keychain};
use chrono::{DateTime, Utc};
use grin_core::core::{transaction as tx, KernelFeatures, TxKernel};
use grin_core::libtx::secp_ser;
use grin_core::ser;
use grin_keychain::SwitchCommitmentType;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::pedersen::{Commitment, RangeProof};
use grin_util::secp::{Message as SecpMessage, Secp256k1, Signature};
use grin_util::to_hex;
use libwallet::{NodeClient, Slate, TxWrapper};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Swap {
	pub id: Uuid,
	pub idx: u32,
	pub version: u8,
	pub address: Option<String>,
	pub network: Network,
	pub role: Role,
	pub started: DateTime<Utc>,
	pub status: Status,
	#[serde(with = "secp_ser::string_or_u64")]
	pub primary_amount: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub secondary_amount: u64,
	pub secondary_currency: Currency,
	pub secondary_data: SecondaryData,
	#[serde(
		serialize_with = "option_pubkey_to_hex",
		deserialize_with = "option_pubkey_from_hex"
	)]
	pub(super) redeem_public: Option<PublicKey>,
	pub(super) participant_id: usize,
	pub(super) multisig: MultisigBuilder,
	#[serde(deserialize_with = "slate_deser")]
	pub(super) lock_slate: Slate,
	pub(super) lock_confirmations: Option<u64>,
	#[serde(deserialize_with = "slate_deser")]
	pub(super) refund_slate: Slate,
	#[serde(deserialize_with = "slate_deser")]
	pub(super) redeem_slate: Slate,
	pub(super) redeem_confirmations: Option<u64>,
	#[serde(
		serialize_with = "option_sig_to_hex",
		deserialize_with = "option_sig_from_hex"
	)]
	pub(super) adaptor_signature: Option<Signature>,
}

impl Swap {
	pub fn is_finalized(&self) -> bool {
		use Status::*;

		match self.status {
			Completed | Cancelled | Refunded => true,
			_ => false,
		}
	}

	pub fn is_seller(&self) -> bool {
		match self.role {
			Role::Seller(_, _) => true,
			Role::Buyer => false,
		}
	}

	pub fn redeem_output(&self) -> Result<Option<(u64, Commitment)>, ErrorKind> {
		let output = match self.redeem_slate.tx.outputs().get(0) {
			Some(o) => o.commit.clone(),
			None => return Ok(None),
		};

		Ok(Some((self.redeem_slate.amount, output)))
	}

	pub(super) fn expect_seller(&self) -> Result<(), ErrorKind> {
		match self.role {
			Role::Seller(_, _) => Ok(()),
			_ => Err(ErrorKind::UnexpectedRole),
		}
	}

	pub(super) fn expect_buyer(&self) -> Result<(), ErrorKind> {
		match self.role {
			Role::Buyer => Ok(()),
			_ => Err(ErrorKind::UnexpectedRole),
		}
	}

	pub(super) fn unwrap_seller(&self) -> Result<(String, u64), ErrorKind> {
		match &self.role {
			Role::Seller(address, change) => Ok((address.clone(), *change)),
			_ => Err(ErrorKind::UnexpectedRole),
		}
	}

	pub(super) fn expect(&self, status: Status) -> Result<(), ErrorKind> {
		if self.status == status {
			Ok(())
		} else {
			Err(ErrorKind::UnexpectedStatus(status, self.status))
		}
	}

	pub(super) fn message(&self, inner: Update) -> Result<Message, ErrorKind> {
		Ok(Message::new(self.id.clone(), inner, SecondaryUpdate::Empty))
	}

	pub(super) fn multisig_secret<K: Keychain>(
		&self,
		keychain: &K,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let sec_key = keychain.derive_key(
			self.primary_amount,
			&context.multisig_key,
			&SwitchCommitmentType::None,
		)?;

		Ok(sec_key)
	}

	pub(super) fn refund_amount(&self) -> u64 {
		self.primary_amount - self.refund_slate.fee
	}

	pub(super) fn update_lock_confirmations<C: NodeClient>(
		&mut self,
		secp: &Secp256k1,
		node_client: &C,
	) -> Result<u64, ErrorKind> {
		let commit = self.multisig.commit(secp)?;
		let outputs = node_client.get_outputs_from_node(vec![commit])?;
		let height = node_client.get_chain_height()?;
		for (commit_out, (_, height_out, _)) in outputs {
			if commit_out == commit {
				let confirmations = height.saturating_sub(height_out) + 1;
				self.lock_confirmations = Some(confirmations);
				return Ok(confirmations);
			}
		}

		Ok(0)
	}

	pub(super) fn redeem_tx_fields(
		&self,
		secp: &Secp256k1,
	) -> Result<(PublicKey, PublicKey, SecpMessage), ErrorKind> {
		let pub_nonces = self
			.redeem_slate
			.participant_data
			.iter()
			.map(|p| &p.public_nonce)
			.collect();
		let pub_nonce_sum = PublicKey::from_combination(secp, pub_nonces)?;
		let pub_blinds = self
			.redeem_slate
			.participant_data
			.iter()
			.map(|p| &p.public_blind_excess)
			.collect();
		let pub_blind_sum = PublicKey::from_combination(secp, pub_blinds)?;

		let features = KernelFeatures::Plain {
			fee: self.redeem_slate.fee,
		};
		let message = features
			.kernel_sig_msg()
			.map_err(|_| ErrorKind::Generic("Unable to generate message".into()))?;

		Ok((pub_nonce_sum, pub_blind_sum, message))
	}

	pub(super) fn find_redeem_kernel<C: NodeClient>(
		&self,
		node_client: &mut C,
	) -> Result<Option<(TxKernel, u64)>, ErrorKind> {
		let excess = &self
			.redeem_slate
			.tx
			.kernels()
			.get(0)
			.ok_or(ErrorKind::UnexpectedAction)?
			.excess;

		let res = node_client
			.get_kernel(excess, None, None)?
			.map(|(kernel, height, _)| (kernel, height));

		Ok(res)
	}

	pub(super) fn is_locked(&self, confirmations: u64) -> bool {
		self.lock_confirmations.unwrap_or(0) >= confirmations
	}

	pub(super) fn other_participant_id(&self) -> usize {
		(self.participant_id + 1) % 2
	}

	/// Common nonce for the BulletProof is sum_i H(C_i) where C_i is the commitment of participant i
	pub(super) fn common_nonce(&self, secp: &Secp256k1) -> Result<SecretKey, ErrorKind> {
		let hashed_nonces: Vec<SecretKey> = self
			.multisig
			.participants
			.iter()
			.filter_map(|p| p.partial_commitment.as_ref().map(|c| c.hash()))
			.filter_map(|h| h.ok().map(|h| h.to_secret_key(secp)))
			.filter_map(|s| s.ok())
			.collect();
		if hashed_nonces.len() != 2 {
			return Err(super::multisig::ErrorKind::MultiSigIncomplete.into());
		}
		let sec_key = secp.blind_sum(hashed_nonces, Vec::new())?;

		Ok(sec_key)
	}
}

impl ser::Writeable for Swap {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

impl ser::Readable for Swap {
	fn read(reader: &mut dyn ser::Reader) -> Result<Swap, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|_| ser::Error::CorruptedData)
	}
}

/// Add an input to a tx at the appropriate position
pub fn tx_add_input(slate: &mut Slate, commit: Commitment) {
	let input = tx::Input {
		features: tx::OutputFeatures::Plain,
		commit,
	};
	let inputs = slate.tx.inputs_mut();
	inputs
		.binary_search(&input)
		.err()
		.map(|e| inputs.insert(e, input));
}

/// Add an output to a tx at the appropriate position
pub fn tx_add_output(slate: &mut Slate, commit: Commitment, proof: RangeProof) {
	let output = tx::Output {
		features: tx::OutputFeatures::Plain,
		commit,
		proof,
	};
	let outputs = slate.tx.outputs_mut();
	outputs
		.binary_search(&output)
		.err()
		.map(|e| outputs.insert(e, output));
}

/// Interpret the final 32 bytes of the signature as a secret key
pub fn signature_as_secret(
	secp: &Secp256k1,
	signature: &Signature,
) -> Result<SecretKey, ErrorKind> {
	let ser = signature.to_raw_data();
	let key = SecretKey::from_slice(secp, &ser[32..])?;
	Ok(key)
}

/// Serialize a transaction and submit it to the network
pub fn publish_transaction<C: NodeClient>(
	node_client: &C,
	tx: &tx::Transaction,
	fluff: bool,
) -> Result<(), ErrorKind> {
	let wrapper = TxWrapper {
		tx_hex: to_hex(ser::ser_vec(tx, ser::ProtocolVersion::local()).unwrap()),
	};
	node_client.post_tx(&wrapper, fluff)?;
	Ok(())
}
