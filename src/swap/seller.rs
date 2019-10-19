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

use super::message::*;
use super::multisig::{Builder as MultisigBuilder, ParticipantData as MultisigParticipant};
use super::swap::{publish_transaction, signature_as_secret, tx_add_input, tx_add_output, Swap};
use super::types::*;
use super::{is_test_mode, ErrorKind, Keychain, CURRENT_SLATE_VERSION, CURRENT_VERSION};
use chrono::{TimeZone, Utc};
use grin_core::libtx::{build, proof, tx_fee};
use grin_keychain::{BlindSum, BlindingFactor};
use grin_util::secp::aggsig;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::pedersen::{Commitment, RangeProof};
use libwallet::{NodeClient, ParticipantData as TxParticipant, Slate, VersionedSlate};
use rand::thread_rng;
use std::mem;
use uuid::Uuid;

pub struct SellApi {}

impl SellApi {
	/// Start a swap
	/// This will create an object to track the swap state,
	/// as well as an offer to send to the counterparty
	/// It assumes that the Context has already been populated with
	/// the correct values for key derivation paths and nonces
	pub fn create_swap_offer<K: Keychain>(
		keychain: &K,
		context: &Context,
		address: Option<String>,
		primary_amount: u64,
		secondary_amount: u64,
		secondary_currency: Currency,
		secondary_redeem_address: String,
		height: u64,
	) -> Result<Swap, ErrorKind> {
		let test_mode = is_test_mode();
		let scontext = context.unwrap_seller()?;
		let multisig = MultisigBuilder::new(
			2,
			primary_amount,
			false,
			0,
			context.multisig_nonce.clone(),
			None,
		);

		// Lock slate
		let mut lock_slate = Slate::blank(2);
		if test_mode {
			lock_slate.id = Uuid::parse_str("55b79f54-c40d-45e1-9544-a52dcf426db2").unwrap();
		}
		lock_slate.fee = tx_fee(scontext.inputs.len(), 2, 1, None);
		lock_slate.amount = primary_amount;
		lock_slate.height = height;

		// Refund slate
		let mut refund_slate = Slate::blank(2);
		if test_mode {
			refund_slate.id = Uuid::parse_str("703fac15-913c-4e66-a7c2-5f648ca4ca7d").unwrap();
		}
		refund_slate.fee = tx_fee(1, 1, 1, None);
		refund_slate.height = height;
		refund_slate.lock_height = height + 12 * 60;

		// Redeem slate
		let mut redeem_slate = Slate::blank(2);
		if test_mode {
			redeem_slate.id = Uuid::parse_str("fc750aae-035f-4c6c-bb0c-05aabc764f8e").unwrap();
		}

		// Make sure we have enough funds
		let mut sum_in = 0;
		for (_, input_amount) in &scontext.inputs {
			sum_in += *input_amount;
		}

		// TODO: no change output if amounts match up exactly
		if sum_in <= primary_amount + lock_slate.fee {
			return Err(ErrorKind::InsufficientFunds(
				primary_amount + lock_slate.fee + 1,
				sum_in,
			));
		}
		let change = sum_in - primary_amount - lock_slate.fee;

		let id = if test_mode {
			Uuid::parse_str("4fc16adb-9f32-4441-b0c1-b4de076a1972").unwrap()
		} else {
			Uuid::new_v4()
		};

		let started = if test_mode {
			Utc.ymd(2019, 9, 4).and_hms_micro(21, 22, 32, 581245)
		} else {
			Utc::now()
		};

		let mut swap = Swap {
			id,
			idx: 0,
			version: CURRENT_VERSION,
			address,
			network: Network::Floonet,
			role: Role::Seller(secondary_redeem_address, change),
			started,
			status: Status::Created,
			primary_amount,
			secondary_amount,
			secondary_currency,
			secondary_data: SecondaryData::Empty,
			redeem_public: None,
			participant_id: 0,
			multisig,
			lock_slate,
			lock_confirmations: None,
			refund_slate,
			redeem_slate,
			redeem_confirmations: None,
			adaptor_signature: None,
		};

		Self::build_multisig(keychain, &mut swap, context)?;
		Self::build_lock_slate(keychain, &mut swap, context)?;
		Self::build_refund_slate(keychain, &mut swap, context)?;
		Self::build_redeem_participant(keychain, &mut swap, context)?;

		Ok(swap)
	}

	pub fn accepted_offer<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		accept_offer: AcceptOfferUpdate,
	) -> Result<(), ErrorKind> {
		swap.expect_seller()?;
		swap.expect(Status::Offered)?;

		// Finalize multisig proof
		let proof = Self::finalize_multisig(keychain, swap, context, accept_offer.multisig)?;

		// Update slates
		let commit = swap.multisig.commit(keychain.secp())?;
		Self::finalize_lock_slate(
			keychain,
			swap,
			context,
			commit.clone(),
			proof,
			accept_offer.lock_participant,
		)?;
		Self::finalize_refund_slate(
			keychain,
			swap,
			context,
			commit.clone(),
			accept_offer.refund_participant,
		)?;

		swap.redeem_public = Some(accept_offer.redeem_public);
		swap.status = Status::Accepted;

		Ok(())
	}

	pub fn init_redeem<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		init_redeem: InitRedeemUpdate,
	) -> Result<(), ErrorKind> {
		swap.expect_seller()?;
		match swap.status {
			Status::Accepted | Status::Locked => {}
			s => return Err(ErrorKind::UnexpectedStatus(Status::Locked, s)),
		}

		// This function should only be called once
		if swap.adaptor_signature.is_some() {
			return Err(ErrorKind::OneShot.into());
		}

		let mut redeem_slate: Slate = init_redeem.redeem_slate.into();

		// Validate adaptor signature
		let (pub_nonce_sum, _, message) = swap.redeem_tx_fields(keychain.secp(), &redeem_slate)?;
		// Calculate sum of blinding factors from in- and outputs so we know we can use this excess
		// later to find the on-chain signature and calculate the redeem secret
		let pub_blind_sum =
			Self::redeem_excess(keychain, &mut redeem_slate)?.to_pubkey(keychain.secp())?;
		if !aggsig::verify_single(
			keychain.secp(),
			&init_redeem.adaptor_signature,
			&message,
			Some(&pub_nonce_sum),
			&redeem_slate.participant_data[swap.other_participant_id()].public_blind_excess,
			Some(&pub_blind_sum),
			Some(&swap.redeem_public.ok_or(ErrorKind::UnexpectedAction)?),
			true,
		) {
			return Err(ErrorKind::InvalidAdaptorSignature);
		}

		swap.redeem_slate = redeem_slate;
		swap.adaptor_signature = Some(init_redeem.adaptor_signature);

		Self::sign_redeem_slate(keychain, swap, context)?;

		// If the multisig outputs are already locked, we can start the redeem stage
		if swap.status == Status::Locked {
			swap.status = Status::InitRedeem;
		}

		Ok(())
	}

	pub fn calculate_redeem_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
	) -> Result<SecretKey, ErrorKind> {
		let secp = keychain.secp();

		let adaptor_signature = signature_as_secret(
			secp,
			&swap.adaptor_signature.ok_or(ErrorKind::UnexpectedAction)?,
		)?;
		let signature = signature_as_secret(
			secp,
			&swap
				.redeem_slate
				.tx
				.kernels()
				.get(0)
				.ok_or(ErrorKind::UnexpectedAction)?
				.excess_sig,
		)?;
		let seller_signature = signature_as_secret(
			secp,
			&swap
				.redeem_slate
				.participant_data
				.get(swap.participant_id)
				.ok_or(ErrorKind::UnexpectedAction)?
				.part_sig
				.ok_or(ErrorKind::UnexpectedAction)?,
		)?;

		let redeem = secp.blind_sum(vec![adaptor_signature, seller_signature], vec![signature])?;
		let redeem_pub = PublicKey::from_secret_key(keychain.secp(), &redeem)?;
		if swap.redeem_public != Some(redeem_pub) {
			return Err(ErrorKind::Generic(
				"Redeem secret doesn't match - this should never happen".into(),
			));
		}

		Ok(redeem)
	}

	pub fn message(swap: &Swap) -> Result<Message, ErrorKind> {
		match swap.status {
			Status::Created => Self::offer_message(swap),
			Status::InitRedeem => Self::redeem_message(swap),
			_ => Err(ErrorKind::UnexpectedAction),
		}
	}

	/// Update swap state after a message has been sent succesfully
	pub fn message_sent(swap: &mut Swap) -> Result<(), ErrorKind> {
		match swap.status {
			Status::Created => swap.status = Status::Offered,
			Status::InitRedeem => swap.status = Status::Redeem,
			_ => return Err(ErrorKind::UnexpectedAction),
		};

		Ok(())
	}

	pub fn publish_transaction<C: NodeClient>(
		node_client: &C,
		swap: &mut Swap,
	) -> Result<(), ErrorKind> {
		match swap.status {
			Status::Accepted => {
				if swap.lock_confirmations.is_some() {
					// Tx already published
					return Err(ErrorKind::UnexpectedAction);
				}
				publish_transaction(node_client, &swap.lock_slate.tx, false)?;
				swap.lock_confirmations = Some(0);
				Ok(())
			}
			_ => Err(ErrorKind::UnexpectedAction),
		}
	}

	/// Required action based on current swap state
	pub fn required_action<C: NodeClient>(
		node_client: &mut C,
		swap: &mut Swap,
	) -> Result<Action, ErrorKind> {
		if swap.status == Status::Locked && swap.adaptor_signature.is_some() {
			// There's a race condition between receiving the message from the buyer and
			// updating the status to Locked based on the number of confirmations
			// If we are here, we received the message before the lock
			// so we can update the status to start the redeem
			swap.status = Status::InitRedeem;
		}

		let action = match swap.status {
			Status::Created => Action::SendMessage(1),
			Status::Offered => Action::ReceiveMessage,
			Status::Accepted => unreachable!(), // Should be handled by currency specific API
			Status::Locked => Action::ReceiveMessage,
			Status::InitRedeem => Action::SendMessage(2),
			Status::Redeem => {
				if swap.redeem_confirmations.unwrap_or(0) == 0 {
					match swap.find_redeem_kernel(node_client)? {
						Some((kernel, h)) => {
							let height = node_client.get_chain_height()?;
							swap.redeem_confirmations = Some(height.saturating_sub(h) + 1);

							// Replace kernel
							mem::replace(
								swap.redeem_slate
									.tx
									.kernels_mut()
									.get_mut(0)
									.ok_or(ErrorKind::UnexpectedAction)?,
								kernel,
							);

							// Currency specific API should claim the funds on the secondary chain
							// But from the perspective of this API, we're done
							Action::Complete
						}
						None => Action::ConfirmationRedeem,
					}
				} else {
					Action::Complete
				}
			}
			_ => Action::None,
		};
		Ok(action)
	}

	pub fn offer_message(swap: &Swap) -> Result<Message, ErrorKind> {
		swap.expect_seller()?;
		swap.expect(Status::Created)?;
		swap.message(Update::Offer(OfferUpdate {
			version: swap.version,
			network: swap.network,
			primary_amount: swap.primary_amount,
			secondary_amount: swap.secondary_amount,
			secondary_currency: swap.secondary_currency,
			multisig: swap.multisig.export()?,
			lock_slate: VersionedSlate::into_version(
				swap.lock_slate.clone(),
				CURRENT_SLATE_VERSION,
			),
			refund_slate: VersionedSlate::into_version(
				swap.refund_slate.clone(),
				CURRENT_SLATE_VERSION,
			),
			redeem_participant: swap.redeem_slate.participant_data[swap.participant_id].clone(),
		}))
	}

	pub fn redeem_message(swap: &Swap) -> Result<Message, ErrorKind> {
		swap.expect_seller()?;
		swap.expect(Status::InitRedeem)?;
		swap.message(Update::Redeem(RedeemUpdate {
			redeem_participant: swap.redeem_slate.participant_data[swap.participant_id].clone(),
		}))
	}

	fn build_multisig<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let multisig_secret = swap.multisig_secret(keychain, context)?;
		let multisig = &mut swap.multisig;

		// Round 1
		multisig.create_participant(keychain.secp(), &multisig_secret)?;
		multisig.round_1(keychain.secp(), &multisig_secret)?;

		Ok(())
	}

	fn finalize_multisig<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: MultisigParticipant,
	) -> Result<RangeProof, ErrorKind> {
		let sec_key = swap.multisig_secret(keychain, context)?;
		let secp = keychain.secp();

		// Import
		let multisig = &mut swap.multisig;
		multisig.import_participant(1, &part)?;
		multisig.round_1_participant(1, &part)?;
		multisig.round_2_participant(1, &part)?;

		// Round 2 + finalize
		let common_nonce = swap.common_nonce(secp)?;
		let multisig = &mut swap.multisig;
		multisig.common_nonce = Some(common_nonce);
		multisig.round_2(secp, &sec_key)?;
		let proof = multisig.finalize(secp, &sec_key)?;

		Ok(proof)
	}

	/// Convenience function to calculate the secret that is used for signing the lock slate
	fn lock_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let scontext = context.unwrap_seller()?;
		let (_, change) = swap.unwrap_seller()?;
		let mut sum = BlindSum::new();

		// Input(s)
		for (input_identifier, input_amount) in &scontext.inputs {
			sum = sum.sub_key_id(input_identifier.to_value_path(*input_amount));
		}

		// Change output, partial multisig output, offset
		sum = sum
			.add_key_id(scontext.change_output.to_value_path(change))
			.add_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(keychain, context)?,
			))
			.sub_blinding_factor(swap.lock_slate.tx.offset.clone());
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_lock_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let (_, change) = swap.unwrap_seller()?;
		let scontext = context.unwrap_seller()?;

		// This function should only be called once
		let slate = &mut swap.lock_slate;
		if slate.participant_data.len() > 0 {
			return Err(ErrorKind::OneShot.into());
		}

		// Build lock slate
		// The multisig output is missing because it is not yet fully known
		let mut elems = Vec::with_capacity(4);
		elems.push(build::with_fee(slate.fee));
		for (input_identifier, input_amount) in &scontext.inputs {
			elems.push(build::input(*input_amount, input_identifier.clone()));
		}
		elems.push(build::output(change, scontext.change_output.clone()));
		slate.add_transaction_elements(keychain, &proof::ProofBuilder::new(keychain), elems)?;
		slate.tx.offset = if is_test_mode() {
			BlindingFactor::from_hex(
				"d9da697c9c8bf7ff85116dd401f53e4d58bc0155fb6db56b15a99aa8884a44e9",
			)
			.unwrap()
		} else {
			BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()))
		};

		let mut sec_key = Self::lock_tx_secret(keychain, swap, context)?;
		let slate = &mut swap.lock_slate;

		// Add participant to slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.lock_nonce,
			swap.participant_id,
			None,
			false,
		)?;

		Ok(())
	}

	fn finalize_lock_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		commit: Commitment,
		proof: RangeProof,
		part: TxParticipant,
	) -> Result<(), ErrorKind> {
		let sec_key = Self::lock_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.lock_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot.into());
		}

		// Add participant to slate
		slate.participant_data.push(part);

		// Add multisig output to slate
		tx_add_output(slate, commit, proof);

		// Sign + finalize slate
		slate.fill_round_2(keychain, &sec_key, &context.lock_nonce, swap.participant_id)?;
		slate.finalize(keychain)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn refund_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let scontext = context.unwrap_seller()?;

		// Partial multisig input, refund output, offset
		let sum = BlindSum::new()
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(keychain, context)?,
			))
			.add_key_id(scontext.refund_output.to_value_path(swap.refund_amount()))
			.sub_blinding_factor(swap.refund_slate.tx.offset.clone());
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_refund_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let scontext = context.unwrap_seller()?;
		let refund_amount = swap.refund_amount();

		// This function should only be called once
		let slate = &mut swap.refund_slate;
		if slate.participant_data.len() > 0 {
			return Err(ErrorKind::OneShot);
		}

		// Build refund slate
		// The multisig input is missing because it is not yet fully known
		let mut elems = Vec::with_capacity(3);
		elems.push(build::with_lock_height(slate.lock_height));
		elems.push(build::with_fee(slate.fee));
		elems.push(build::output(refund_amount, scontext.refund_output.clone()));
		slate
			.add_transaction_elements(keychain, &proof::ProofBuilder::new(keychain), elems)?
			.secret_key(keychain.secp())?;
		slate.tx.offset = if is_test_mode() {
			BlindingFactor::from_hex(
				"53ac7d0ad9833568cf63dfa8aa607e2b27be525111b1e0de92aa0caa50f838ae",
			)
			.unwrap()
		} else {
			BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()))
		};

		let mut sec_key = Self::refund_tx_secret(keychain, swap, context)?;
		let slate = &mut swap.refund_slate;

		// Add participant to slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.refund_nonce,
			swap.participant_id,
			None,
			false,
		)?;

		Ok(())
	}

	fn finalize_refund_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		commit: Commitment,
		part: TxParticipant,
	) -> Result<(), ErrorKind> {
		let sec_key = Self::refund_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.refund_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot.into());
		}

		// Add participant to slate
		slate.participant_data.push(part);

		// Add multisig input to slate
		tx_add_input(slate, commit);

		// Sign + finalize slate
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.refund_nonce,
			swap.participant_id,
		)?;
		slate.finalize(keychain)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn redeem_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		// Partial multisig input
		let sum = BlindSum::new().sub_blinding_factor(BlindingFactor::from_secret_key(
			swap.multisig_secret(keychain, context)?,
		));
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_redeem_participant<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate.participant_data.len() > 0 {
			return Err(ErrorKind::OneShot);
		}

		// Build participant
		let participant = TxParticipant {
			id: swap.participant_id as u64,
			public_blind_excess: PublicKey::from_secret_key(keychain.secp(), &sec_key)?,
			public_nonce: PublicKey::from_secret_key(keychain.secp(), &context.redeem_nonce)?,
			part_sig: None,
			message: None,
			message_sig: None,
		};
		slate.participant_data.push(participant);

		Ok(())
	}

	fn redeem_excess<K: Keychain>(
		keychain: &K,
		redeem_slate: &mut Slate,
	) -> Result<Commitment, ErrorKind> {
		let excess = redeem_slate.calc_excess(keychain)?;
		redeem_slate.tx.kernels_mut()[0].excess = excess.clone();
		Ok(excess)
	}

	fn sign_redeem_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let id = swap.participant_id;
		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate.participant_data[id].is_complete() {
			return Err(ErrorKind::OneShot);
		}

		// Sign slate
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.redeem_nonce,
			swap.participant_id,
		)?;

		Ok(())
	}
}
