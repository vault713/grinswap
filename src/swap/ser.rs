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

use failure::Error;
//use grin_core::core::{Input as TxInput, KernelFeatures, Output as TxOutput, OutputFeatures, Transaction, TransactionBody, TxKernel};
//use grin_keychain::BlindingFactor;
//use grin_util::secp::constants::MAX_PROOF_SIZE;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::pedersen::Commitment;
//use grin_util::secp::pedersen::RangeProof;
use grin_util::secp::{ContextFlag, Secp256k1, Signature};
use hex::{self, FromHex};
use libwallet::{Slate, VersionedSlate};
use serde::{Deserialize, Deserializer, Serializer};
//use uuid::Uuid;

// Slate
pub fn slate_deser<'a, D>(deserializer: D) -> Result<Slate, D::Error>
where
	D: Deserializer<'a>,
{
	let s = VersionedSlate::deserialize(deserializer)?;
	Ok(s.into())
}

// Vec<u8>
pub fn bytes_to_hex<S>(key: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(&hex::encode(key))
}

pub fn bytes_from_hex<'a, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let s = String::deserialize(deserializer)?;
	Vec::from_hex(&s).map_err(D::Error::custom)
}

/*pub fn option_bytes_to_hex<S>(key: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match key {
		Some(inner) => serializer.serialize_str(&hex::encode(inner)),
		None => serializer.serialize_none(),
	}
}

pub fn option_bytes_from_hex<'a, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	let opt = match opt {
		Some(s) => Some(Vec::from_hex(&s).map_err(D::Error::custom)?),
		None => None,
	};
	Ok(opt)
}*/

// Commitment
pub fn commit_to_hex<S>(key: &Commitment, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(&hex::encode(key.0.to_vec()))
}

fn commit_from_hex_string(s: String) -> Result<Commitment, Error> {
	let v = Vec::from_hex(&s)?;
	Ok(Commitment::from_vec(v))
}

/*pub fn commit_from_hex<'a, D>(deserializer: D) -> Result<Commitment, D::Error>
	where D: Deserializer<'a>
{
	use serde::de::Error;
	let s = String::deserialize(deserializer)?;
	commit_from_hex_string(s)
		.map_err(D::Error::custom)
}*/

// Option<Commitment>
pub fn option_commit_to_hex<S>(key: &Option<Commitment>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match key {
		Some(inner) => commit_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

pub fn option_commit_from_hex<'a, D>(deserializer: D) -> Result<Option<Commitment>, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	match opt {
		Some(s) => commit_from_hex_string(s)
			.map(|p| Some(p))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}

// PublicKey
pub fn pubkey_to_hex<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	let s = Secp256k1::with_caps(ContextFlag::None);
	serializer.serialize_str(&hex::encode(key.serialize_vec(&s, true)))
}

fn pubkey_from_hex_string(s: String) -> Result<PublicKey, Error> {
	let v = Vec::from_hex(&s)?;
	let s = Secp256k1::with_caps(ContextFlag::None);
	let p = PublicKey::from_slice(&s, &v[..])?;
	Ok(p)
}

pub fn pubkey_from_hex<'a, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let s = String::deserialize(deserializer)?;
	pubkey_from_hex_string(s).map_err(D::Error::custom)
}

// Option<PublicKey>
pub fn option_pubkey_to_hex<S>(key: &Option<PublicKey>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match key {
		Some(inner) => pubkey_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

pub fn option_pubkey_from_hex<'a, D>(deserializer: D) -> Result<Option<PublicKey>, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	match opt {
		Some(s) => pubkey_from_hex_string(s)
			.map(|p| Some(p))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}

// SecretKey
pub fn seckey_to_hex<S>(key: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(&hex::encode(&key.0))
}

fn seckey_from_hex_string(s: String) -> Result<SecretKey, Error> {
	let v = Vec::from_hex(&s)?;
	let s = Secp256k1::with_caps(ContextFlag::None);
	let sk = SecretKey::from_slice(&s, &v[..])?;
	Ok(sk)
}

pub fn seckey_from_hex<'a, D>(deserializer: D) -> Result<SecretKey, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let s = String::deserialize(deserializer)?;
	seckey_from_hex_string(s).map_err(D::Error::custom)
}

// Option<SecretKey>
pub fn option_seckey_to_hex<S>(key: &Option<SecretKey>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match key {
		Some(inner) => seckey_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

pub fn option_seckey_from_hex<'a, D>(deserializer: D) -> Result<Option<SecretKey>, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	match opt {
		Some(s) => seckey_from_hex_string(s)
			.map(|s| Some(s))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}

// BlindingFactor
/*pub fn blind_to_hex<S>(key: &BlindingFactor, serializer: S) -> Result<S::Ok, S::Error>
	where S: Serializer
{
	serializer.serialize_str(&hex::encode(key.as_ref()))
}

fn blind_from_hex_string(s: String) -> Result<BlindingFactor, Error> {
	let v = Vec::from_hex(&s)?;
	let b = BlindingFactor::from_slice(&v[..]);
	Ok(b)
}

pub fn blind_from_hex<'a, D>(deserializer: D) -> Result<BlindingFactor, D::Error>
	where D: Deserializer<'a>
{
	use serde::de::Error;
	let s = String::deserialize(deserializer)?;
	blind_from_hex_string(s)
		.map_err(D::Error::custom)
}*/

// RangeProof
/*pub fn proof_to_hex<S>(proof: &RangeProof, serializer: S) -> Result<S::Ok, S::Error>
	where S: Serializer
{
	serializer.serialize_str(&hex::encode(&proof.proof.to_vec()))
}

fn proof_from_hex_string(s: String) -> Result<RangeProof, Error> {
	let v = Vec::from_hex(&s)?;
	let plen = v.len().min(MAX_PROOF_SIZE as usize);
	let mut proof: [u8; MAX_PROOF_SIZE] = [0; MAX_PROOF_SIZE];
	for i in 0..plen {
		proof[i] = v[i];
	}
	Ok(RangeProof {
		proof,
		plen
	})
}

pub fn proof_from_hex<'a, D>(deserializer: D) -> Result<RangeProof, D::Error>
	where D: Deserializer<'a>
{
	use serde::de::Error;
	let s = String::deserialize(deserializer)?;
	proof_from_hex_string(s)
		.map_err(D::Error::custom)
}

// Option<RangeProof>
pub fn option_proof_to_hex<S>(proof: &Option<RangeProof>, serializer: S) -> Result<S::Ok, S::Error>
	where S: Serializer
{
	match proof {
		Some(inner) => proof_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

pub fn option_proof_from_hex<'a, D>(deserializer: D) -> Result<Option<RangeProof>, D::Error>
	where D: Deserializer<'a>
{
	use serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	match opt {
		Some(s) => {
			proof_from_hex_string(s)
				.map(|p| Some(p))
				.map_err(D::Error::custom)
		},
		None => Ok(None),
	}
}*/

// Signature
pub fn sig_to_hex<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	let s = Secp256k1::with_caps(ContextFlag::None);
	serializer.serialize_str(&hex::encode(sig.serialize_compact(&s).to_vec()))
}

fn sig_from_hex_string(s: String) -> Result<Signature, Error> {
	let v = Vec::from_hex(&s)?;
	let s = Secp256k1::with_caps(ContextFlag::None);
	let sig = Signature::from_compact(&s, &v[..])?;
	Ok(sig)
}

pub fn sig_from_hex<'a, D>(deserializer: D) -> Result<Signature, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let s = String::deserialize(deserializer)?;
	sig_from_hex_string(s).map_err(D::Error::custom)
}

// Option<Signature>
pub fn option_sig_to_hex<S>(sig: &Option<Signature>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match sig {
		Some(inner) => sig_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

pub fn option_sig_from_hex<'a, D>(deserializer: D) -> Result<Option<Signature>, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	match opt {
		Some(s) => sig_from_hex_string(s)
			.map(|sig| Some(sig))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}

/*#[derive(Serialize, Deserialize, Debug)]
pub struct TxSlateDummy {
	pub num_participants: usize,
	pub id: Uuid,
	pub tx: TransactionDummy,
	pub amount: u64,
	pub fee: u64,
	pub height: u64,
	pub lock_height: u64,
	pub participant_data: Vec<TxParticipantDataDummy>,
}

impl From<TxSlate> for TxSlateDummy {
	fn from(slate: TxSlate) -> Self {
		let mut participant_data = vec![];
		for participant in slate.participant_data {
			participant_data.push(participant.into());
		}

		Self {
			num_participants: slate.num_participants,
			id: slate.id,
			tx: slate.tx.into(),
			amount: slate.amount,
			fee: slate.fee,
			height: slate.height,
			lock_height: slate.lock_height,
			participant_data
		}
	}
}

impl From<TxSlateDummy> for TxSlate {
	fn from(dummy: TxSlateDummy) -> Self {
		let mut participant_data = vec![];
		for participant in dummy.participant_data {
			participant_data.push(participant.into());
		}

		Self {
			num_participants: dummy.num_participants,
			id: dummy.id,
			tx: dummy.tx.into(),
			amount: dummy.amount,
			fee: dummy.fee,
			height: dummy.height,
			lock_height: dummy.lock_height,
			participant_data
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionDummy {
	#[serde(serialize_with = "blind_to_hex", deserialize_with = "blind_from_hex")]
	pub offset: BlindingFactor,
	pub body: TransactionBodyDummy
}

impl From<Transaction> for TransactionDummy {
	fn from(tx: Transaction) -> Self {
		let offset = tx.offset;
		let body: TransactionBody = tx.into();
		Self {
			offset,
			body: body.into()
		}
	}
}

impl From<TransactionDummy> for Transaction {
	fn from(dummy: TransactionDummy) -> Self {
		let offset = dummy.offset;
		let body: TransactionBody = dummy.body.into();
		Transaction::new(body.inputs, body.outputs, body.kernels)
			.with_offset(offset)
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionBodyDummy {
	pub inputs: Vec<TxInputDummy>,
	pub outputs: Vec<TxOutputDummy>,
	pub kernels: Vec<TxKernelDummy>
}

impl From<TransactionBody> for TransactionBodyDummy {
	fn from(body: TransactionBody) -> Self {
		let mut inputs = vec![];
		for input in body.inputs {
			inputs.push(input.into());
		}
		let mut outputs = vec![];
		for output in body.outputs {
			outputs.push(output.into());
		}
		let mut kernels = vec![];
		for kernel in body.kernels {
			kernels.push(kernel.into());
		}

		Self {
			inputs,
			outputs,
			kernels,
		}
	}
}

impl From<TransactionBodyDummy> for TransactionBody {
	fn from(dummy: TransactionBodyDummy) -> Self {
		let mut inputs = vec![];
		for input in dummy.inputs {
			inputs.push(input.into());
		}
		let mut outputs = vec![];
		for output in dummy.outputs {
			outputs.push(output.into());
		}
		let mut kernels = vec![];
		for kernel in dummy.kernels {
			kernels.push(kernel.into());
		}

		Self {
			inputs,
			outputs,
			kernels
		}
	}
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TxInputDummy {
	pub features: u8,
	#[serde(serialize_with = "commit_to_hex", deserialize_with = "commit_from_hex")]
	pub commit: Commitment
}

impl From<TxInput> for TxInputDummy {
	fn from(input: TxInput) -> Self {
		Self {
			features: input.features.bits(),
			commit: input.commit
		}
	}
}

impl From<TxInputDummy> for TxInput {
	fn from(dummy: TxInputDummy) -> Self {
		Self {
			features: OutputFeatures::from_bits_truncate(dummy.features),
			commit: dummy.commit
		}
	}
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TxOutputDummy {
	pub features: u8,
	#[serde(serialize_with = "commit_to_hex", deserialize_with = "commit_from_hex")]
	pub commit: Commitment,
	#[serde(serialize_with = "proof_to_hex", deserialize_with = "proof_from_hex")]
	pub proof: RangeProof,
}

impl From<TxOutput> for TxOutputDummy {
	fn from(output: TxOutput) -> Self {
		Self {
			features: output.features.bits(),
			commit: output.commit,
			proof: output.proof
		}
	}
}

impl From<TxOutputDummy> for TxOutput {
	fn from(dummy: TxOutputDummy) -> Self {
		Self {
			features: OutputFeatures::from_bits_truncate(dummy.features),
			commit: dummy.commit,
			proof: dummy.proof
		}
	}
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TxKernelDummy {
	pub features: u8,
	pub fee: u64,
	pub lock_height: u64,
	#[serde(serialize_with = "commit_to_hex", deserialize_with = "commit_from_hex")]
	pub excess: Commitment,
	#[serde(serialize_with = "sig_to_hex", deserialize_with = "sig_from_hex")]
	pub excess_sig: Signature,
}

impl From<TxKernel> for TxKernelDummy {
	fn from(kernel: TxKernel) -> Self {
		Self {
			features: kernel.features.bits(),
			fee: kernel.fee,
			lock_height: kernel.lock_height,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig
		}
	}
}

impl From<TxKernelDummy> for TxKernel {
	fn from(dummy: TxKernelDummy) -> Self {
		Self {
			features: KernelFeatures::from_bits_truncate(dummy.features),
			fee: dummy.fee,
			lock_height: dummy.lock_height,
			excess: dummy.excess,
			excess_sig: dummy.excess_sig
		}
	}
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TxParticipantDataDummy {
	pub id: u64,
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub public_blind_excess: PublicKey,
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub public_nonce: PublicKey,
	#[serde(serialize_with = "option_sig_to_hex", deserialize_with = "option_sig_from_hex", skip_serializing_if = "Option::is_none", default)]
	pub part_sig: Option<Signature>,
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub message: Option<String>,
	#[serde(serialize_with = "option_sig_to_hex", deserialize_with = "option_sig_from_hex", skip_serializing_if = "Option::is_none", default)]
	pub message_sig: Option<Signature>,

}

impl From<TxParticipantData> for TxParticipantDataDummy {
	fn from(data: TxParticipantData) -> Self {
		Self {
			id: data.id,
			public_blind_excess: data.public_blind_excess,
			public_nonce: data.public_nonce,
			part_sig: data.part_sig,
			message: data.message,
			message_sig: data.message_sig
		}
	}
}

impl From<TxParticipantDataDummy> for TxParticipantData {
	fn from(dummy: TxParticipantDataDummy) -> Self {
		Self {
			id: dummy.id,
			public_blind_excess: dummy.public_blind_excess,
			public_nonce: dummy.public_nonce,
			part_sig: dummy.part_sig,
			message: dummy.message,
			message_sig: dummy.message_sig
		}
	}
}*/
