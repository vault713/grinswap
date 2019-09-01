use super::error::ErrorKind;
use super::message::Message;
use super::swap::Swap;
use super::types::{Action, Context};

pub trait SwapAPI {
	/// Seller creates a swap offer
	fn create_swap_offer(
		&mut self,
		context: &Context,
		primary_amount: u64,
		secondary_amount: u64,
		secondary_redeem_address: String,
	) -> Result<(Swap, Action), ErrorKind>;

	/// Buyer accepts a swap offer
	fn accept_swap_offer(
		&mut self,
		context: &Context,
		message: Message,
	) -> Result<(Swap, Action), ErrorKind>;

	fn completed(&mut self, swap: &mut Swap, context: &Context) -> Result<Action, ErrorKind>;

	fn refunded(&mut self, swap: &mut Swap) -> Result<(), ErrorKind>;

	fn cancelled(&mut self, swap: &mut Swap) -> Result<(), ErrorKind>;

	/// Check which action should be taken by the user
	fn required_action(&mut self, swap: &mut Swap, context: &Context) -> Result<Action, ErrorKind>;

	fn message(&self, swap: &Swap) -> Result<Message, ErrorKind>;

	/// Message has been sent to the counter-party, update state accordingly
	fn message_sent(&mut self, swap: &mut Swap, context: &Context) -> Result<Action, ErrorKind>;

	/// Apply an update Message to the Swap
	fn receive_message(
		&mut self,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<Action, ErrorKind>;

	fn publish_transaction(
		&mut self,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;

	fn publish_secondary_transaction(
		&mut self,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;
}
