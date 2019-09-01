use super::client::BTCNodeClient;
use super::types::BTCData;
use crate::swap::message::{Message, Update};
use crate::swap::swap::publish_transaction;
use crate::swap::types::{Action, Context, Currency, Role, Status};
use crate::swap::{BuyAPI, ErrorKind, SellAPI, Swap, SwapAPI};
use bitcoin::{Address, AddressType};
use grin_core::core::Transaction;
use grin_keychain::{Keychain, SwitchCommitmentType};
use libwallet::NodeClient;
use std::str::FromStr;
use std::time::Duration;

pub struct BTCSwapAPI<K, C, B>
where
	K: Keychain,
	C: NodeClient,
	B: BTCNodeClient,
{
	keychain: K,
	node_client: C,
	btc_node_client: B,
}

impl<K, C, B> BTCSwapAPI<K, C, B>
where
	K: Keychain,
	C: NodeClient,
	B: BTCNodeClient,
{
	/// Create BTC Swap API instance
	pub fn new(keychain: K, node_client: C, btc_node_client: B) -> Self {
		Self {
			keychain,
			node_client,
			btc_node_client,
		}
	}

	fn script(&self, swap: &mut Swap) -> Result<(), ErrorKind> {
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		btc_data.script(
			self.keychain.secp(),
			swap.redeem_public
				.as_ref()
				.ok_or(ErrorKind::UnexpectedAction)?,
		)?;
		Ok(())
	}

	fn btc_balance(
		&mut self,
		swap: &mut Swap,
		confirmations_needed: u64,
	) -> Result<(u64, u64, u64), ErrorKind> {
		self.script(swap)?;
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		let address = btc_data.address(swap.network)?;
		let outputs = self.btc_node_client.unspent(&address)?;
		let height = self.btc_node_client.height()?;
		let mut pending_amount = 0;
		let mut confirmed_amount = 0;
		let mut least_confirmations = None;

		let mut confirmed_outputs = Vec::new();

		for output in outputs {
			if output.height == 0 {
				// Output in mempool
				least_confirmations = Some(0);
				pending_amount += output.value;
			} else {
				let confirmations = height.saturating_sub(output.height) + 1;
				if confirmations >= confirmations_needed {
					// Enough confirmations
					confirmed_amount += output.value;
					confirmed_outputs.push(output);
				} else {
					// Not yet enough confirmations
					if least_confirmations
						.map(|least| confirmations < least)
						.unwrap_or(true)
					{
						least_confirmations = Some(confirmations);
					}
					pending_amount += output.value;
				}
			}
		}
		btc_data.confirmed_outputs = confirmed_outputs;

		Ok((
			pending_amount,
			confirmed_amount,
			least_confirmations.unwrap_or(0),
		))
	}

	// Seller specific methods

	/// Seller checks Grin and Bitcoin chains for the locked funds
	fn seller_check_locks(&mut self, swap: &mut Swap) -> Result<Option<Action>, ErrorKind> {
		// Check Grin chain
		if !swap.is_locked(30) {
			match swap.lock_confirmations {
				None => return Ok(Some(Action::PublishTx)),
				Some(_) => {
					let confirmations =
						swap.update_lock_confirmations(self.keychain.secp(), &self.node_client)?;
					if !swap.is_locked(30) {
						return Ok(Some(Action::Confirmations {
							required: 30,
							actual: confirmations,
						}));
					}
				}
			};
		}

		// Check Bitcoin chain
		if !swap.secondary_data.unwrap_btc()?.locked {
			let (pending_amount, confirmed_amount, mut least_confirmations) =
				self.btc_balance(swap, 6)?;
			if pending_amount + confirmed_amount < swap.secondary_amount {
				least_confirmations = 0;
			};

			if confirmed_amount < swap.secondary_amount {
				return Ok(Some(Action::ConfirmationsSecondary {
					required: 6,
					actual: least_confirmations,
				}));
			}

			swap.secondary_data.unwrap_btc_mut()?.locked = true;
		}

		// If we got here, funds have been locked on both chains with sufficient confirmations
		swap.status = Status::Locked;

		Ok(None)
	}

	/// Seller applies an update message to the Swap
	fn seller_receive_message(
		&self,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		match swap.status {
			Status::Offered => self.seller_accepted_offer(swap, context, message),
			Status::Locked => self.seller_init_redeem(swap, context, message),
			_ => Err(ErrorKind::UnexpectedMessageType),
		}
	}

	/// Seller applies accepted offer message from buyer to the swap
	fn seller_accepted_offer(
		&self,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		let (_, accept_offer, secondary_update) = message.unwrap_accept_offer()?;
		let btc_update = secondary_update.unwrap_btc()?.unwrap_accept_offer()?;

		SellAPI::accepted_offer(&self.keychain, swap, context, accept_offer)?;
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		btc_data.accepted_offer(btc_update)?;

		Ok(())
	}

	/// Seller applies accepted offer message from buyer to the swap
	fn seller_init_redeem(
		&self,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		let (_, init_redeem, _) = message.unwrap_init_redeem()?;
		SellAPI::init_redeem(&self.keychain, swap, context, init_redeem)?;

		Ok(())
	}

	/// Seller builds the transaction to redeem their Bitcoins
	fn seller_build_redeem_tx(&self, swap: &mut Swap, context: &Context) -> Result<(), ErrorKind> {
		swap.expect(Status::Redeem)?;
		self.script(swap)?;
		let cosign_id = &context.unwrap_seller()?.unwrap_btc()?.cosign;

		let redeem_address = Address::from_str(&swap.unwrap_seller()?.0)
			.map_err(|_| ErrorKind::Generic("Unable to parse BTC redeem address".into()))?;

		let cosign_secret = self
			.keychain
			.derive_key(0, cosign_id, &SwitchCommitmentType::None)?;
		let redeem_secret = SellAPI::calculate_redeem_secret(&self.keychain, swap)?;

		// This function should only be called once
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		if btc_data.redeem_tx.is_some() {
			return Err(ErrorKind::OneShot)?;
		}

		btc_data.redeem_tx(
			self.keychain.secp(),
			&redeem_address,
			10,
			&cosign_secret,
			&redeem_secret,
		)?;
		swap.status = Status::RedeemSecondary;

		Ok(())
	}

	fn seller_redeem_confirmations(&self, swap: &mut Swap) -> Result<(), ErrorKind> {
		Ok(())
	}

	// Buyer specific methods

	/// Buyer checks Grin and Bitcoin chains for the locked funds
	fn buyer_check_locks(
		&mut self,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Option<Action>, ErrorKind> {
		// Check Bitcoin chain
		if !swap.secondary_data.unwrap_btc()?.locked {
			let (pending_amount, confirmed_amount, least_confirmations) =
				self.btc_balance(swap, 6)?;
			let chain_amount = pending_amount + confirmed_amount;
			if chain_amount < swap.secondary_amount {
				// At this point, user needs to deposit (more) Bitcoin
				self.script(swap)?;
				return Ok(Some(Action::DepositSecondary {
					amount: swap.secondary_amount - chain_amount,
					address: format!(
						"{}",
						swap.secondary_data.unwrap_btc()?.address(swap.network)?
					),
				}));
			}

			// Enough confirmed or in mempool
			if confirmed_amount < swap.secondary_amount {
				// Wait for enough confirmations
				return Ok(Some(Action::ConfirmationsSecondary {
					required: 6,
					actual: least_confirmations,
				}));
			}

			swap.secondary_data.unwrap_btc_mut()?.locked = true;
		}

		// Check Grin chain
		let confirmations =
			swap.update_lock_confirmations(self.keychain.secp(), &self.node_client)?;
		if !swap.is_locked(30) {
			return Ok(Some(Action::Confirmations {
				required: 30,
				actual: confirmations,
			}));
		}

		// If we got here, funds have been locked on both chains with sufficient confirmations
		swap.status = Status::Locked;
		BuyAPI::init_redeem(&self.keychain, swap, context)?;

		Ok(None)
	}

	/// Buyer applies an update message to the Swap
	fn buyer_receive_message(
		&self,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		match swap.status {
			Status::InitRedeem => self.buyer_redeem(swap, context, message),
			_ => Err(ErrorKind::UnexpectedMessageType),
		}
	}

	/// Buyer applies redeem message from seller to the swap
	fn buyer_redeem(
		&self,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		let (_, redeem, _) = message.unwrap_redeem()?;
		BuyAPI::redeem(&self.keychain, swap, context, redeem)?;
		Ok(())
	}
}

impl<K, C, B> SwapAPI for BTCSwapAPI<K, C, B>
where
	K: Keychain,
	C: NodeClient,
	B: BTCNodeClient,
{
	/// Seller creates a swap offer
	fn create_swap_offer(
		&mut self,
		context: &Context,
		primary_amount: u64,
		secondary_amount: u64,
		secondary_redeem_address: String,
	) -> Result<(Swap, Action), ErrorKind> {
		let address = Address::from_str(&secondary_redeem_address)
			.map_err(|_| ErrorKind::Generic("Unable to parse BTC redeem address".into()))?;

		match address.address_type() {
			Some(AddressType::P2pkh) | Some(AddressType::P2sh) => {}
			_ => {
				return Err(ErrorKind::Generic(
					"Only P2PKH and P2SH BTC redeem addresses are supported".into(),
				))
			}
		};

		let height = self.node_client.get_chain_height()?;
		let mut swap = SellAPI::create_swap_offer(
			&self.keychain,
			context,
			primary_amount,
			secondary_amount,
			Currency::BTC,
			secondary_redeem_address,
			height,
		)?;

		let btc_data = BTCData::new(
			&self.keychain,
			context.unwrap_seller()?.unwrap_btc()?,
			Duration::from_secs(24 * 60 * 60),
		)?;
		swap.secondary_data = btc_data.wrap();

		let action = self.required_action(&mut swap, context)?;
		Ok((swap, action))
	}

	/// Buyer accepts a swap offer
	fn accept_swap_offer(
		&mut self,
		context: &Context,
		message: Message,
	) -> Result<(Swap, Action), ErrorKind> {
		let (id, offer, secondary_update) = message.unwrap_offer()?;
		let btc_data = BTCData::from_offer(
			&self.keychain,
			secondary_update.unwrap_btc()?.unwrap_offer()?,
			context.unwrap_buyer()?.unwrap_btc()?,
		)?;

		let height = self.node_client.get_chain_height()?;
		let mut swap = BuyAPI::accept_swap_offer(&self.keychain, context, id, offer, height)?;
		swap.secondary_data = btc_data.wrap();

		let action = self.required_action(&mut swap, context)?;
		Ok((swap, action))
	}

	fn completed(&mut self, swap: &mut Swap, context: &Context) -> Result<Action, ErrorKind> {
		match swap.role {
			Role::Seller(_, _) => {
				swap.expect(Status::RedeemSecondary)?;
				let btc_data = swap.secondary_data.unwrap_btc()?;
				if btc_data.redeem_confirmations.unwrap_or(0) > 0 {
					swap.status = Status::Completed;
				} else {
					return Err(ErrorKind::UnexpectedAction);
				}
			}
			Role::Buyer => BuyAPI::completed(swap)?,
		}
		let action = self.required_action(swap, context)?;

		Ok(action)
	}

	fn refunded(&mut self, swap: &mut Swap) -> Result<(), ErrorKind> {
		unimplemented!();
	}

	fn cancelled(&mut self, swap: &mut Swap) -> Result<(), ErrorKind> {
		unimplemented!();
	}

	/// Check which action should be taken by the user
	fn required_action(&mut self, swap: &mut Swap, context: &Context) -> Result<Action, ErrorKind> {
		if swap.finalized() {
			return Ok(Action::None);
		}

		let action = match swap.role {
			Role::Seller(_, _) => {
				if swap.status == Status::Accepted {
					if let Some(action) = self.seller_check_locks(swap)? {
						return Ok(action);
					}
				} else if swap.status == Status::RedeemSecondary {
					// We have generated the BTC redeem tx..
					let btc_data = swap.secondary_data.unwrap_btc_mut()?;
					let txid = &btc_data
						.redeem_tx
						.as_ref()
						.ok_or(ErrorKind::Generic("Redeem transaction missing".into()))?
						.txid;
					if btc_data.redeem_confirmations.is_none() {
						// ..but we haven't published it yet
						return Ok(Action::PublishTxSecondary);
					} else {
						// ..we published it..
						if let Some((Some(height), _)) = self.btc_node_client.transaction(txid)? {
							let confirmations =
								self.btc_node_client.height()?.saturating_sub(height) + 1;
							btc_data.redeem_confirmations = Some(confirmations);
							if confirmations > 0 {
								// ..and its been included in a block!
								return Ok(Action::Complete);
							}
						}
						// ..but its not confirmed yet
						return Ok(Action::ConfirmationRedeemSecondary(format!("{}", txid)));
					}
				}
				let action = SellAPI::required_action(&mut self.node_client, swap)?;

				match (swap.status, action) {
					(Status::Redeem, Action::Complete) => {
						self.seller_build_redeem_tx(swap, context)?;
						Action::PublishTxSecondary
					}
					(_, action) => action,
				}
			}
			Role::Buyer => {
				if swap.status == Status::Accepted {
					if let Some(action) = self.buyer_check_locks(swap, context)? {
						return Ok(action);
					}
				}
				BuyAPI::required_action(&mut self.node_client, swap)?
			}
		};

		Ok(action)
	}

	fn message(&self, swap: &Swap) -> Result<Message, ErrorKind> {
		let message = match swap.role {
			Role::Seller(_, _) => {
				let mut message = SellAPI::message(swap)?;
				if let Update::Offer(_) = message.inner {
					message.set_inner_secondary(
						swap.secondary_data.unwrap_btc()?.offer_update().wrap(),
					);
				}
				message
			}
			Role::Buyer => {
				let mut message = BuyAPI::message(swap)?;
				if let Update::AcceptOffer(_) = message.inner {
					message.set_inner_secondary(
						swap.secondary_data
							.unwrap_btc()?
							.accept_offer_update()?
							.wrap(),
					);
				}
				message
			}
		};

		Ok(message)
	}

	/// Message has been sent to the counterparty, update state accordingly
	fn message_sent(&mut self, swap: &mut Swap, context: &Context) -> Result<Action, ErrorKind> {
		match swap.role {
			Role::Seller(_, _) => SellAPI::message_sent(swap)?,
			Role::Buyer => BuyAPI::message_sent(swap)?,
		}
		let action = self.required_action(swap, context)?;

		Ok(action)
	}

	/// Apply an update Message to the Swap
	fn receive_message(
		&mut self,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<Action, ErrorKind> {
		if swap.id != message.id {
			return Err(ErrorKind::MismatchedId);
		}

		if swap.finalized() {
			return Err(ErrorKind::Finalized);
		}

		match swap.role {
			Role::Seller(_, _) => self.seller_receive_message(swap, context, message)?,
			Role::Buyer => self.buyer_receive_message(swap, context, message)?,
		};
		let action = self.required_action(swap, context)?;

		Ok(action)
	}

	fn publish_transaction(
		&mut self,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind> {
		match swap.role {
			Role::Seller(_, _) => SellAPI::publish_transaction(&self.node_client, swap),
			Role::Buyer => BuyAPI::publish_transaction(&self.node_client, swap),
		}?;

		self.required_action(swap, context)
	}

	fn publish_secondary_transaction(
		&mut self,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind> {
		swap.expect_seller()?;
		swap.expect(Status::RedeemSecondary)?;
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		if btc_data.redeem_confirmations.is_some() {
			return Err(ErrorKind::UnexpectedAction);
		}

		let tx = btc_data
			.redeem_tx
			.as_ref()
			.ok_or(ErrorKind::UnexpectedAction)?
			.tx
			.clone();
		self.btc_node_client.post_tx(tx)?;
		btc_data.redeem_confirmations = Some(0);
		let action = self.required_action(swap, context)?;

		Ok(action)
	}
}
