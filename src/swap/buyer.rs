use super::message::*;
use super::swap::{publish_transaction, tx_add_input, tx_add_output, Swap};
use super::types::*;
use super::{ErrorKind, Keychain, CURRENT_SLATE_VERSION, CURRENT_VERSION};
use crate::swap::multisig::{Builder as MultisigBuilder, ParticipantData as MultisigParticipant};
use chrono::Utc;
use grin_core::libtx::{build, proof, tx_fee};
use grin_keychain::{BlindSum, BlindingFactor, SwitchCommitmentType};
use grin_util::secp::aggsig;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::pedersen::RangeProof;
use libwallet::{NodeClient, ParticipantData as TxParticipant, Slate, VersionedSlate};
use rand::thread_rng;
use std::mem;
use uuid::Uuid;

pub struct BuyApi {}

impl BuyApi {
	pub fn accept_swap_offer<K: Keychain>(
		keychain: &K,
		context: &Context,
		address: Option<String>,
		id: Uuid,
		offer: OfferUpdate,
		height: u64,
	) -> Result<Swap, ErrorKind> {
		if offer.version != CURRENT_VERSION {
			return Err(ErrorKind::IncompatibleVersion);
		}

		context.unwrap_buyer()?;

		// Multisig tx needs to be unlocked
		let lock_slate: Slate = offer.lock_slate.into();
		if lock_slate.lock_height > 0 {
			return Err(ErrorKind::InvalidLockHeightLockTx);
		}

		// Refund tx needs to be locked until at least 10 hours in the future
		let refund_slate: Slate = offer.refund_slate.into();
		if refund_slate.lock_height < height + 10 * 60 {
			return Err(ErrorKind::InvalidLockHeightRefundTx);
		}

		// Start redeem slate
		let mut redeem_slate = Slate::blank(2);
		redeem_slate.participant_data.push(offer.redeem_participant);

		let multisig = MultisigBuilder::new(
			2,
			offer.primary_amount,
			false,
			1,
			context.multisig_nonce.clone(),
			None,
		);

		let mut swap = Swap {
			id,
			idx: 0,
			version: CURRENT_VERSION,
			address,
			network: offer.network,
			role: Role::Buyer,
			started: Utc::now(),
			status: Status::Offered,
			primary_amount: offer.primary_amount,
			secondary_amount: offer.secondary_amount,
			secondary_currency: offer.secondary_currency,
			secondary_data: SecondaryData::Empty,
			redeem_public: None,
			participant_id: 1,
			multisig,
			lock_slate,
			lock_confirmations: None,
			refund_slate,
			redeem_slate,
			redeem_confirmations: None,
			adaptor_signature: None,
		};

		swap.redeem_public = Some(PublicKey::from_secret_key(
			keychain.secp(),
			&Self::redeem_secret(keychain, context)?,
		)?);

		Self::build_multisig(keychain, &mut swap, context, offer.multisig)?;
		Self::sign_lock_slate(keychain, &mut swap, context)?;
		Self::sign_refund_slate(keychain, &mut swap, context)?;

		Ok(swap)
	}

	pub fn init_redeem<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		swap.expect_buyer()?;
		swap.expect(Status::Locked)?;

		Self::build_redeem_slate(keychain, swap, context)?;
		Self::calculate_adaptor_signature(keychain, swap, context)?;

		Ok(())
	}

	pub fn redeem<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		redeem: RedeemUpdate,
	) -> Result<(), ErrorKind> {
		swap.expect_buyer()?;
		swap.expect(Status::InitRedeem)?;

		Self::finalize_redeem_slate(keychain, swap, context, redeem.redeem_participant)?;
		swap.status = Status::Redeem;

		Ok(())
	}

	pub fn completed(swap: &mut Swap) -> Result<(), ErrorKind> {
		swap.expect_buyer()?;
		swap.expect(Status::Redeem)?;
		match swap.redeem_confirmations {
			Some(h) if h > 0 => {
				swap.status = Status::Completed;
				Ok(())
			}
			_ => Err(ErrorKind::UnexpectedAction),
		}
	}

	pub fn message(swap: &Swap) -> Result<Message, ErrorKind> {
		match swap.status {
			Status::Offered => Self::accept_offer_message(swap),
			Status::Locked => Self::init_redeem_message(swap),
			_ => Err(ErrorKind::UnexpectedAction),
		}
	}

	/// Update swap state after a message has been sent succesfully
	pub fn message_sent(swap: &mut Swap) -> Result<(), ErrorKind> {
		match swap.status {
			Status::Offered => swap.status = Status::Accepted,
			Status::Locked => swap.status = Status::InitRedeem,
			_ => return Err(ErrorKind::UnexpectedAction),
		};

		Ok(())
	}

	pub fn publish_transaction<C: NodeClient>(
		node_client: &C,
		swap: &mut Swap,
	) -> Result<(), ErrorKind> {
		match swap.status {
			Status::Redeem => {
				if swap.redeem_confirmations.is_some() {
					// Tx already published
					return Err(ErrorKind::UnexpectedAction);
				}
				publish_transaction(node_client, &swap.redeem_slate.tx, false)?;
				swap.redeem_confirmations = Some(0);
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
		let action = match swap.status {
			Status::Offered => Action::SendMessage(1),
			Status::Accepted => unreachable!(), // Should be handled by currency specific API
			Status::Locked => Action::SendMessage(2),
			Status::InitRedeem => Action::ReceiveMessage,
			Status::Redeem => {
				if swap.redeem_confirmations.is_none() {
					Action::PublishTx
				} else {
					// Update confirmations
					match swap.find_redeem_kernel(node_client)? {
						Some((_, h)) => {
							let height = node_client.get_chain_height()?;
							swap.redeem_confirmations = Some(height.saturating_sub(h) + 1);
							Action::Complete
						}
						None => Action::ConfirmationRedeem,
					}
				}
			}
			_ => Action::None,
		};
		Ok(action)
	}

	pub fn accept_offer_message(swap: &Swap) -> Result<Message, ErrorKind> {
		swap.expect(Status::Offered)?;

		let id = swap.participant_id;
		swap.message(Update::AcceptOffer(AcceptOfferUpdate {
			multisig: swap.multisig.export()?,
			redeem_public: swap.redeem_public.unwrap().clone(),
			lock_participant: swap.lock_slate.participant_data[id].clone(),
			refund_participant: swap.refund_slate.participant_data[id].clone(),
		}))
	}

	pub fn init_redeem_message(swap: &Swap) -> Result<Message, ErrorKind> {
		swap.expect(Status::Locked)?;

		swap.message(Update::InitRedeem(InitRedeemUpdate {
			redeem_slate: VersionedSlate::into_version(
				swap.redeem_slate.clone(),
				CURRENT_SLATE_VERSION,
			),
			adaptor_signature: swap.adaptor_signature.ok_or(ErrorKind::UnexpectedAction)?,
		}))
	}

	/// Secret that unlocks the funds on both chains
	fn redeem_secret<K: Keychain>(keychain: &K, context: &Context) -> Result<SecretKey, ErrorKind> {
		let bcontext = context.unwrap_buyer()?;
		let sec_key = keychain.derive_key(0, &bcontext.redeem, &SwitchCommitmentType::None)?;

		Ok(sec_key)
	}

	fn build_multisig<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: MultisigParticipant,
	) -> Result<(), ErrorKind> {
		let multisig_secret = swap.multisig_secret(keychain, context)?;
		let multisig = &mut swap.multisig;

		// Import participant
		multisig.import_participant(0, &part)?;
		multisig.create_participant(keychain.secp(), &multisig_secret)?;
		multisig.round_1_participant(0, &part)?;

		// Round 1 + round 2
		multisig.round_1(keychain.secp(), &multisig_secret)?;
		let common_nonce = swap.common_nonce(keychain.secp())?;
		let multisig = &mut swap.multisig;
		multisig.common_nonce = Some(common_nonce);
		multisig.round_2(keychain.secp(), &multisig_secret)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the lock slate
	fn lock_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		// Partial multisig output
		let sum = BlindSum::new().add_blinding_factor(BlindingFactor::from_secret_key(
			swap.multisig_secret(keychain, context)?,
		));
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn sign_lock_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let mut sec_key = Self::lock_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.lock_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot.into());
		}

		// Add multisig output to slate (with invalid proof)
		let mut proof = RangeProof::zero();
		proof.plen = 675;

		tx_add_output(slate, swap.multisig.commit(keychain.secp())?, proof);

		// Sign slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.lock_nonce,
			swap.participant_id,
			None,
			false,
		)?;
		slate.fill_round_2(keychain, &sec_key, &context.lock_nonce, swap.participant_id)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn refund_tx_secret<K: Keychain>(
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

	fn sign_refund_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let commit = swap.multisig.commit(keychain.secp())?;
		let mut sec_key = Self::refund_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.refund_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot.into());
		}

		// Add multisig input to slate
		tx_add_input(slate, commit);

		// Sign slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.refund_nonce,
			swap.participant_id,
			None,
			false,
		)?;
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.refund_nonce,
			swap.participant_id,
		)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the redeem slate
	fn redeem_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let bcontext = context.unwrap_buyer()?;

		// Partial multisig input, redeem output, offset
		let sum = BlindSum::new()
			.add_key_id(bcontext.output.to_value_path(swap.redeem_slate.amount))
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(keychain, context)?,
			))
			.sub_blinding_factor(swap.redeem_slate.tx.offset.clone());
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_redeem_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let bcontext = context.unwrap_buyer()?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot);
		}

		// Build slate
		slate.fee = tx_fee(1, 1, 1, None);
		slate.amount = swap.primary_amount - slate.fee;
		let mut elems = Vec::with_capacity(2);
		elems.push(build::with_fee(slate.fee));
		elems.push(build::output(slate.amount, bcontext.output.clone()));
		slate
			.add_transaction_elements(keychain, &proof::ProofBuilder::new(keychain), elems)?
			.secret_key(keychain.secp())?;
		slate.tx.offset =
			BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()));

		// Add multisig input to slate
		tx_add_input(slate, swap.multisig.commit(keychain.secp())?);

		let mut sec_key = Self::redeem_tx_secret(keychain, swap, context)?;
		let slate = &mut swap.redeem_slate;

		// Add participant to slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.redeem_nonce,
			swap.participant_id,
			None,
			false,
		)?;

		Ok(())
	}

	fn finalize_redeem_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: TxParticipant,
	) -> Result<(), ErrorKind> {
		let id = swap.participant_id;
		let other_id = swap.other_participant_id();
		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate
			.participant_data
			.get(id)
			.ok_or(ErrorKind::UnexpectedAction)?
			.is_complete()
		{
			return Err(ErrorKind::OneShot.into());
		}

		// Replace participant
		mem::replace(
			slate
				.participant_data
				.get_mut(other_id)
				.ok_or(ErrorKind::UnexpectedAction)?,
			part,
		);

		// Sign + finalize slate
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.redeem_nonce,
			swap.participant_id,
		)?;
		slate.finalize(keychain)?;

		Ok(())
	}

	fn calculate_adaptor_signature<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		// This function should only be called once
		if swap.adaptor_signature.is_some() {
			return Err(ErrorKind::OneShot);
		}

		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;
		let (pub_nonce_sum, pub_blind_sum, message) = swap.redeem_tx_fields(keychain.secp())?;

		let adaptor_signature = aggsig::sign_single(
			keychain.secp(),
			&message,
			&sec_key,
			Some(&context.redeem_nonce),
			Some(&Self::redeem_secret(keychain, context)?),
			Some(&pub_nonce_sum),
			Some(&pub_blind_sum),
			Some(&pub_nonce_sum),
		)?;
		swap.adaptor_signature = Some(adaptor_signature);

		Ok(())
	}
}
