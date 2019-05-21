use blake2::blake2b::blake2b;
use failure::Error;
use grin_core::core::{Input as TxInput, Output as TxOutput, OutputFeatures};
use hex::FromHex;
use secp::Secp256k1;
use secp::constants::SECRET_KEY_SIZE;
use secp::key::{PublicKey, SecretKey};
use secp::pedersen::{Commitment, RangeProof};
use serde::{Deserialize, Deserializer, Serializer, Serialize};

use crate::swap::ser::*;
use super::error::ErrorKind;

#[derive(Serialize, Deserialize, Debug)]
pub struct Builder {
	num_participants: usize,
    amount: u64,
    participants: Vec<ParticipantData>,
	#[serde(serialize_with = "option_proof_to_hex", deserialize_with = "option_proof_from_hex", skip_serializing_if = "Option::is_none", default)]
    proof: Option<RangeProof>,

	id: usize,
	nonce: SecretKey,
	common_nonce: SecretKey,
}

impl Builder {
	pub fn new(num_participants: usize, amount: u64, id: usize, nonce: SecretKey, common_nonce: SecretKey) -> Self {
		Self {
			num_participants,
			amount,
			participants: vec![],
			proof: None,
			id,
			nonce,
			common_nonce,
		}
	}

	pub fn create_participant(&mut self, secp: &Secp256k1, secret_key: &SecretKey) -> Result<(), Error> {
		let id = self.participants.len();
		if id != self.id {
			return Err(ErrorKind::ParticipantOrdering.into());
		}
		let partial_commitment = secp.commit(0, *secret_key)?;
		self.participants.push(ParticipantData::new(partial_commitment));
		Ok(())
	}

	pub fn import_participant(&mut self, id: usize, participant: &ParticipantData) -> Result<(), Error> {
		if self.participants.len() > id {
			return Err(ErrorKind::ParticipantExists.into());
		}

		if self.participants.len() != id && self.participants.len() >= self.num_participants {
			return Err(ErrorKind::ParticipantOrdering.into());
		}

		self.participants.push(participant.new_foreign());
		Ok(())
	}

	pub fn reveal_participant(&mut self, id: usize, participant: &ParticipantData) -> Result<(), Error> {
		if self.participants.len() <= id {
			return Err(ErrorKind::ParticipantDoesntExist.into());
		}

		if self.participants.len() != self.num_participants {
			return Err(ErrorKind::MultiSigIncomplete.into());
		}

		match participant.partial_commitment.as_ref() {
			Some(p) => self.participants[id].reveal(p),
			None => Err(ErrorKind::Reveal.into()),
		}
	}

	pub fn round_1_participant(&mut self, id: usize, participant: &ParticipantData) -> Result<(), Error> {
		if self.participants.len() <= id {
			return Err(ErrorKind::ParticipantDoesntExist.into());
		}

		if self.participants.len() != self.num_participants {
			return Err(ErrorKind::MultiSigIncomplete.into());
		}

		if participant.t_1.is_none() || participant.t_2.is_none() {
			return Err(ErrorKind::Round1Missing.into());
		}

		self.participants[id].t_1 = participant.t_1;
		self.participants[id].t_2 = participant.t_2;
		Ok(())
	}

	pub fn round_2_participant(&mut self, id: usize, participant: &ParticipantData) -> Result<(), Error> {
		if self.participants.len() <= id {
			return Err(ErrorKind::ParticipantDoesntExist.into());
		}

		if self.participants.len() != self.num_participants {
			return Err(ErrorKind::MultiSigIncomplete.into());
		}

		if participant.tau_x.is_none() {
			return Err(ErrorKind::Round2Missing.into());
		}

		self.participants[id].tau_x = participant.tau_x;
		Ok(())
	}

	pub fn export(&self) -> Result<ParticipantData, Error> {
		if self.participants.len() <= self.id {
			return Err(ErrorKind::ParticipantDoesntExist.into());
		}

		Ok(self.participants[self.id].clone())
	}


    pub fn reveal(&mut self, secp: &Secp256k1, secret_key: &SecretKey) -> Result<(), Error> {
		if self.participants.len() != self.num_participants {
			return Err(ErrorKind::MultiSigIncomplete.into());
		}

        let partial_commitment = secp.commit(0, *secret_key)?;
        self.participants[self.id].reveal(&partial_commitment)?;
        Ok(())
    }

	pub fn round_1(&mut self, secp: &Secp256k1, blind: &SecretKey) -> Result<(), Error> {
		let mut t_1 = PublicKey::new();
		let mut t_2 = PublicKey::new();
		let commit = self.commit(secp)?;
		secp.bullet_proof_multisig(
			self.amount, blind.clone(), self.common_nonce.clone(), None, None, None,
			Some(&mut t_1), Some(&mut t_2), vec![commit], Some(&self.nonce), 1
		);
		self.participants[self.id].t_1 = Some(t_1);
		self.participants[self.id].t_2 = Some(t_2);
		Ok(())
	}

	pub fn round_2(&mut self, secp: &Secp256k1, blind: &SecretKey) -> Result<(), Error> {
		let mut t_1 = self.sum_t_1(secp)?;
		let mut t_2 = self.sum_t_2(secp)?;
		let mut tau_x = SecretKey([0; SECRET_KEY_SIZE]);
		let commit = self.commit(secp)?;

		secp.bullet_proof_multisig(
			self.amount, blind.clone(), self.common_nonce.clone(), None, None, Some(&mut tau_x),
			Some(&mut t_1), Some(&mut t_2), vec![commit], Some(&self.nonce), 2
		);
		self.participants[self.id].tau_x = Some(tau_x);
		Ok(())
	}

	pub fn finalize(&mut self, secp: &Secp256k1, blind: &SecretKey) -> Result<(), Error> {
		let mut t_1 = self.sum_t_1(secp)?;
		let mut t_2 = self.sum_t_2(secp)?;
		let mut tau_x = self.sum_tau_x(secp)?;
		let commit = self.commit(secp)?;
		let proof = secp.bullet_proof_multisig(
			self.amount, blind.clone(), self.common_nonce.clone(), None, None, Some(&mut tau_x),
			Some(&mut t_1), Some(&mut t_2), vec![commit], Some(&self.nonce), 0
		).ok_or(ErrorKind::MultiSigIncomplete)?;
		secp.verify_bullet_proof(commit, proof, None)?;
		self.proof = Some(proof);
		Ok(())
	}

	pub fn as_input(&self, secp: &Secp256k1) -> Result<TxInput, Error> {
		Ok(TxInput {
			features: OutputFeatures::Plain,
			commit: self.commit(secp)?
		})
	}

	pub fn as_output(&self, secp: &Secp256k1) -> Result<TxOutput, Error> {
		Ok(TxOutput {
			features: OutputFeatures::Plain,
			commit: self.commit(secp)?,
			proof: self.proof.unwrap_or(RangeProof::zero())
		})
	}

	pub fn commit(&self, secp: &Secp256k1) -> Result<Commitment, Error> {
		let mut partial_commitments: Vec<Commitment> = self
			.participants
			.iter()
			.filter_map(|p| p.partial_commitment.clone())
			.collect();

		if partial_commitments.len() != self.num_participants {
			return Err(ErrorKind::MultiSigIncomplete.into());
		}

		let commitment_value = secp.commit_value(self.amount)?;
		partial_commitments.push(commitment_value);
		let commitment = secp.commit_sum(partial_commitments, vec![])?;
		Ok(commitment)
	}

	pub fn proof(&self) -> Result<RangeProof, Error> {
		self.proof.ok_or(ErrorKind::MultiSigIncomplete.into())
	}

	fn sum_t_1(&self, secp: &Secp256k1) -> Result<PublicKey, Error> {
		let t_1s: Vec<&PublicKey> = self
			.participants
			.iter()
			.filter_map(|p| p.t_1.as_ref())
			.collect();

		if t_1s.len() != self.num_participants {
			return Err(ErrorKind::MultiSigIncomplete.into());
		}

		let t_1 = PublicKey::from_combination(secp, t_1s)?;
		Ok(t_1)
	}

	fn sum_t_2(&self, secp: &Secp256k1) -> Result<PublicKey, Error> {
		let t_2s: Vec<&PublicKey> = self
			.participants
			.iter()
			.filter_map(|p| p.t_2.as_ref())
			.collect();

		if t_2s.len() != self.num_participants {
			return Err(ErrorKind::MultiSigIncomplete.into());
		}

		let t_2 = PublicKey::from_combination(secp, t_2s)?;
		Ok(t_2)
	}

	fn sum_tau_x(&self, secp: &Secp256k1) -> Result<SecretKey, Error> {
		let mut sum_tau_x = SecretKey([0; SECRET_KEY_SIZE]);
		let tau_xs: Vec<&SecretKey> = self
			.participants
			.iter()
			.filter_map(|p| p.tau_x.as_ref())
			.collect();

		if tau_xs.len() != self.num_participants {
			return Err(ErrorKind::MultiSigIncomplete.into());
		}

		tau_xs
			.iter()
			.for_each(|x| sum_tau_x.add_assign(&secp, *x).unwrap());
		Ok(sum_tau_x)
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantData {
    partial_commitment_hash: Hash,
	#[serde(serialize_with = "option_commit_to_hex", deserialize_with = "option_commit_from_hex", skip_serializing_if = "Option::is_none", default)]
    partial_commitment: Option<Commitment>,
	#[serde(serialize_with = "option_pubkey_to_hex", deserialize_with = "option_pubkey_from_hex", skip_serializing_if = "Option::is_none", default)]
	t_1: Option<PublicKey>,
	#[serde(serialize_with = "option_pubkey_to_hex", deserialize_with = "option_pubkey_from_hex", skip_serializing_if = "Option::is_none", default)]
	t_2: Option<PublicKey>,
	#[serde(serialize_with = "option_seckey_to_hex", deserialize_with = "option_seckey_from_hex", skip_serializing_if = "Option::is_none", default)]
	tau_x: Option<SecretKey>,
}


impl ParticipantData {
	pub fn new(partial_commitment: Commitment) -> Self {
        ParticipantData {
            partial_commitment_hash: partial_commitment.hash().unwrap(),
			partial_commitment: None,
			t_1: None,
			t_2: None,
			tau_x: None,
		}
	}

	pub fn new_foreign(&self) -> Self {
		ParticipantData {
			partial_commitment_hash: self.partial_commitment_hash.clone(),
			partial_commitment: None,
			t_1: None,
			t_2: None,
			tau_x: None,
		}
	}

    fn reveal(&mut self, partial_commitment: &Commitment) -> Result<(), Error> {
        if partial_commitment.hash()? != self.partial_commitment_hash {
            return Err(ErrorKind::Reveal.into());
        }
        self.partial_commitment = Some(partial_commitment.clone());
        Ok(())
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Hash {
	inner: Vec<u8>,
}

impl Hash {
	pub fn new(inner: Vec<u8>) -> Result<Self, Error> {
		if inner.len() != 32 {
			return Err(ErrorKind::HashLength.into());
		}

		Ok(Self {
			inner,
		})
	}
}

impl Serialize for Hash {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
		serializer.serialize_str(&hex::encode(&self.inner))
	}
}

impl<'de> Deserialize<'de> for Hash {
	fn deserialize<D>(deserializer: D) -> Result<Hash, D::Error>
		where D: Deserializer<'de> {
		use serde::de::Error;
		let s = String::deserialize(deserializer)?;

		let v = Vec::from_hex(&s)
			.map_err(D::Error::custom)?;

		Hash::new(v)
			.map_err(D::Error::custom)
	}
}

trait Hashed {
    fn hash(&self) -> Result<Hash, Error>;
}

impl Hashed for Commitment {
    fn hash(&self) -> Result<Hash, Error> {
		Hash::new(blake2b(32, &[], &self.0).as_bytes().to_vec())
    }
}


#[cfg(test)]
mod tests {
	use rand::thread_rng;
	use secp::ContextFlag;
    use super::*;

	#[test]
	fn test_builder() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		//// Set up phase: parties agree on the participants (and an ordering), amount and a common nonce ////
		let num_participants: usize = 2;
		let amount: u64 = 713_000_000;
		let (common_nonce, _) = secp.generate_keypair(&mut thread_rng()).unwrap();

		//// Commit phase: parties all send their hashed partial commitment to each other (inside the ParticipantData) ////
		// A
		let id_a = 0;
		let (secret_a, _) = secp.generate_keypair(&mut thread_rng()).unwrap();
		let (nonce_a, _) = secp.generate_keypair(&mut thread_rng()).unwrap();
		let mut builder_a = Builder::new(num_participants, amount, id_a, nonce_a, common_nonce.clone());
		assert!(builder_a.create_participant(&secp, &secret_a).is_ok());
		// A cannot reveal yet
		assert!(builder_a.reveal(&secp, &secret_a).is_err());
		let part_a = builder_a.export().unwrap(); // A -> all

		// B
		let id_b = 1;
		let (secret_b, _) = secp.generate_keypair(&mut thread_rng()).unwrap();
		let (nonce_b, _) = secp.generate_keypair(&mut thread_rng()).unwrap();
		let mut builder_b = Builder::new(num_participants, amount, id_b, nonce_b, common_nonce.clone());
		// Participant cannot be created before previous ones are imported
		assert!(builder_b.create_participant(&secp, &secret_b).is_err());
		assert!(builder_b.import_participant(id_a, &part_a).is_ok());
		assert!(builder_b.create_participant(&secp, &secret_b).is_ok());

		//// Reveal phase ////
		// B
		// Revealing with the wrong secret will fail
		assert!(builder_b.reveal(&secp, &secret_a).is_err());
		assert!(builder_b.reveal(&secp, &secret_b).is_ok());
		// A hasn't revealed yet, we don't know the total commitment
		assert!(builder_b.commit(&secp).is_err());
		let part_b = builder_b.export().unwrap(); // B -> all

		// A
		// (import+reveal of B at the same time to save on communication, not required)
		assert!(builder_a.import_participant(id_b, &part_b).is_ok());
		assert!(builder_a.reveal_participant(id_b, &part_b).is_ok());
		assert!(builder_a.reveal(&secp, &secret_a).is_ok());
		assert!(builder_a.commit(&secp).is_ok());

		//// Build phase round 1: T_1 and T_2 ////
		// A
		assert!(builder_a.round_1(&secp, &secret_a).is_ok());
		let part_a = builder_a.export().unwrap(); // A -> all

		// B
		// (reveal+round 1 of A at the same time to save on communication, not required)
		// Round 1 cannot be done without all revealed commitments
		assert!(builder_b.round_1(&secp, &secret_b).is_err());
		// Revealing with the wrong commitment will fail
		assert!(builder_b.reveal_participant(id_a, &part_b).is_err());
		assert!(builder_b.reveal_participant(id_a, &part_a).is_ok());
		// All parties agree on the total commitment
		assert_eq!(builder_a.commit(&secp).unwrap(), builder_b.commit(&secp).unwrap());
		assert!(builder_b.round_1(&secp, &secret_b).is_ok());
		assert!(builder_b.round_1_participant(id_a, &part_a).is_ok());

		//// Build phase round 2: tau_x ////
		// B
		assert!(builder_b.round_2(&secp, &secret_b).is_ok());
		let part_b = builder_b.export().unwrap(); // B -> all

		// A
		// (round 1+round 2 of B at the same time to save on communication, not required)
		// Round 2 cannot be done without all round 1 information
		assert!(builder_a.round_2(&secp, &secret_a).is_err());
		assert!(builder_a.round_1_participant(id_b, &part_b).is_ok());
		// All parties agree on the total T_1 and T_2
		assert_eq!(builder_a.sum_t_1(&secp).unwrap(), builder_b.sum_t_1(&secp).unwrap());
		assert_eq!(builder_a.sum_t_2(&secp).unwrap(), builder_b.sum_t_2(&secp).unwrap());
		assert!(builder_a.round_2(&secp, &secret_a).is_ok());

		//// Finalization phase ////
		// A
		// Finalization cannot be done without all round 2 information
		assert!(builder_a.finalize(&secp, &secret_a).is_err());
		assert!(builder_a.round_2_participant(id_b, &part_b).is_ok());
		assert!(builder_a.finalize(&secp, &secret_a).is_ok());
		// Explicitly verify proof
		let commit_a = builder_a.commit(&secp).unwrap();
		let proof_a = builder_a.proof().unwrap();
		assert!(secp.verify_bullet_proof(commit_a, proof_a, None).is_ok());
		// For completeness, do same on B
		let part_a = builder_a.export().unwrap(); // A -> all

		// B
		assert!(builder_b.round_2_participant(id_a, &part_a).is_ok());
		// All parties agree on the total tau_x
		assert_eq!(builder_a.sum_tau_x(&secp).unwrap(), builder_b.sum_tau_x(&secp).unwrap());
		assert!(builder_b.finalize(&secp, &secret_b).is_ok());
		// Explicitly verify proof
		let commit_b = builder_b.commit(&secp).unwrap();
		let proof_b = builder_b.proof().unwrap();
		assert!(secp.verify_bullet_proof(commit_b, proof_b, None).is_ok());
		// Generated proof is the same
		assert_eq!(proof_a, proof_b);
	}
}