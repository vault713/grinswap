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

use super::error::ErrorKind;
use super::message::Message;
use super::swap::Swap;
use super::types::{Action, Context, Currency};
use super::Keychain;
use grin_keychain::Identifier;

pub trait SwapApi<K: Keychain>: Sync + Send {
	fn context_key_count(
		&mut self,
		secondary_currency: Currency,
		is_seller: bool,
	) -> Result<usize, ErrorKind>;

	fn create_context(
		&mut self,
		keychain: &K,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<(Identifier, u64)>>,
		keys: Vec<Identifier>,
	) -> Result<Context, ErrorKind>;

	/// Seller creates a swap offer
	fn create_swap_offer(
		&mut self,
		keychain: &K,
		context: &Context,
		address: Option<String>,
		primary_amount: u64,
		secondary_amount: u64,
		secondary_currency: Currency,
		secondary_redeem_address: String,
	) -> Result<(Swap, Action), ErrorKind>;

	/// Buyer accepts a swap offer
	fn accept_swap_offer(
		&mut self,
		keychain: &K,
		context: &Context,
		address: Option<String>,
		message: Message,
	) -> Result<(Swap, Action), ErrorKind>;

	fn completed(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;

	fn refunded(&mut self, keychain: &K, swap: &mut Swap) -> Result<(), ErrorKind>;

	fn cancelled(&mut self, keychain: &K, swap: &mut Swap) -> Result<(), ErrorKind>;

	/// Check which action should be taken by the user
	fn required_action(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;

	fn message(&mut self, keychain: &K, swap: &Swap) -> Result<Message, ErrorKind>;

	/// Message has been sent to the counter-party, update state accordingly
	fn message_sent(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;

	/// Apply an update Message to the Swap
	fn receive_message(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<Action, ErrorKind>;

	fn publish_transaction(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;

	fn publish_secondary_transaction(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;
}
