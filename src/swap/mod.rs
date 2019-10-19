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

pub mod api;
pub mod bitcoin;
pub mod buyer;
pub mod error;
pub mod message;
pub mod multisig;
pub mod seller;
pub mod ser;
pub mod swap;
pub mod types;

pub use self::error::ErrorKind;
pub use self::swap::Swap;
pub use self::types::Context;

pub(crate) use self::api::SwapApi;
pub(crate) use self::buyer::BuyApi;
pub(crate) use self::seller::SellApi;

pub use grin_keychain::Keychain;
pub use libwallet::NodeClient;

use libwallet::SlateVersion;
use std::sync::atomic::{AtomicBool, Ordering};

const CURRENT_VERSION: u8 = 1;
const CURRENT_SLATE_VERSION: SlateVersion = SlateVersion::V2;

lazy_static! {
	/// Flag to set test mode
	static ref TEST_MODE: AtomicBool = AtomicBool::new(false);
}

/// Set the test mode
pub fn set_test_mode(mode: bool) {
	TEST_MODE.store(mode, Ordering::Relaxed);
}

/// Check if we are in test mode
pub fn is_test_mode() -> bool {
	TEST_MODE.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
	use crate::bitcoin::network::constants::Network as BtcNetwork;
	use crate::bitcoin::util::key::PublicKey as BtcPublicKey;
	use crate::bitcoin::{Address, Transaction as BtcTransaction, TxOut};
	use grin_core::core::transaction::Weighting;
	use grin_core::core::verifier_cache::LruVerifierCache;
	use grin_core::core::{Transaction, TxKernel};
	use grin_core::ser::{deserialize, ProtocolVersion};
	use grin_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
	use grin_util::secp::key::{PublicKey, SecretKey};
	use grin_util::secp::pedersen::{Commitment, RangeProof};
	use grin_util::{from_hex, to_hex};
	use libwallet::NodeClient;
	use parking_lot::{Mutex, RwLock};
	use std::collections::HashMap;
	use std::fs::{read_to_string, write};
	use std::io::Cursor;
	use std::mem;
	use std::str::FromStr;
	use std::sync::Arc;

	use super::bitcoin::*;
	use super::message::Message;
	use super::types::*;
	use super::*;

	const GRIN_UNIT: u64 = 1_000_000_000;

	fn keychain(idx: u8) -> ExtKeychain {
		let seed_sell: String = format!("fixed0rng0for0testing0purposes0{}", idx % 10);
		let seed_sell = blake2::blake2b::blake2b(32, &[], seed_sell.as_bytes());
		ExtKeychain::from_seed(seed_sell.as_bytes(), false).unwrap()
	}

	fn context_sell(kc: &ExtKeychain) -> Context {
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(kc, 1, 0),
			lock_nonce: key(kc, 1, 1),
			refund_nonce: key(kc, 1, 2),
			redeem_nonce: key(kc, 1, 3),
			role_context: RoleContext::Seller(SellerContext {
				inputs: vec![
					(key_id(0, 1), 60 * GRIN_UNIT),
					(key_id(0, 2), 60 * GRIN_UNIT),
				],
				change_output: key_id(0, 3),
				refund_output: key_id(0, 4),
				secondary_context: SecondarySellerContext::Btc(BtcSellerContext {
					cosign: key_id(0, 5),
				}),
			}),
		}
	}

	fn context_buy(kc: &ExtKeychain) -> Context {
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(kc, 1, 0),
			lock_nonce: key(kc, 1, 1),
			refund_nonce: key(kc, 1, 2),
			redeem_nonce: key(kc, 1, 3),
			role_context: RoleContext::Buyer(BuyerContext {
				output: key_id(0, 1),
				redeem: key_id(0, 2),
				secondary_context: SecondaryBuyerContext::Btc(BtcBuyerContext {
					refund: key_id(0, 3),
				}),
			}),
		}
	}

	fn key_id(d1: u32, d2: u32) -> Identifier {
		ExtKeychain::derive_key_id(2, d1, d2, 0, 0)
	}

	fn key(kc: &ExtKeychain, d1: u32, d2: u32) -> SecretKey {
		kc.derive_key(0, &key_id(d1, d2), &SwitchCommitmentType::None)
			.unwrap()
	}

	fn btc_address(kc: &ExtKeychain) -> String {
		let key = PublicKey::from_secret_key(kc.secp(), &key(kc, 2, 0)).unwrap();
		let address = Address::p2pkh(
			&BtcPublicKey {
				compressed: true,
				key,
			},
			BtcNetwork::Testnet,
		);
		format!("{}", address)
	}

	#[derive(Debug, Clone)]
	struct TestNodeClientState {
		pub height: u64,
		pub pending: Vec<Transaction>,
		pub outputs: HashMap<Commitment, u64>,
		pub kernels: HashMap<Commitment, (TxKernel, u64)>,
	}

	#[derive(Debug, Clone)]
	struct TestNodeClient {
		pub state: Arc<Mutex<TestNodeClientState>>,
	}

	impl TestNodeClient {
		pub fn new(height: u64) -> Self {
			let state = TestNodeClientState {
				height,
				pending: Vec::new(),
				outputs: HashMap::new(),
				kernels: HashMap::new(),
			};
			Self {
				state: Arc::new(Mutex::new(state)),
			}
		}

		pub fn push_output(&self, commit: Commitment) {
			let mut state = self.state.lock();
			let height = state.height;
			state.outputs.insert(commit, height);
		}

		pub fn mine_block(&self) {
			let mut state = self.state.lock();
			state.height += 1;
			let height = state.height;

			let pending = mem::replace(&mut state.pending, Vec::new());
			for tx in pending {
				for input in tx.body.inputs {
					state.outputs.remove(&input.commit);
				}
				for output in tx.body.outputs {
					state.outputs.insert(output.commit, height);
				}
				for kernel in tx.body.kernels {
					state
						.kernels
						.insert(kernel.excess.clone(), (kernel, height));
				}
			}
		}

		pub fn mine_blocks(&self, count: u64) {
			if count > 0 {
				self.mine_block();
				if count > 1 {
					let mut state = self.state.lock();
					state.height += count - 1;
				}
			}
		}
	}

	impl NodeClient for TestNodeClient {
		fn node_url(&self) -> &str {
			unimplemented!()
		}
		fn set_node_url(&mut self, _node_url: &str) {
			unimplemented!()
		}
		fn node_api_secret(&self) -> Option<String> {
			unimplemented!()
		}
		fn set_node_api_secret(&mut self, _node_api_secret: Option<String>) {
			unimplemented!()
		}
		fn post_tx(&self, tx: &libwallet::TxWrapper, _fluff: bool) -> Result<(), libwallet::Error> {
			let wrapper = from_hex(tx.tx_hex.clone()).unwrap();
			let mut cursor = Cursor::new(wrapper);
			let tx: Transaction = deserialize(&mut cursor, ProtocolVersion::local()).unwrap();
			tx.validate(
				Weighting::AsTransaction,
				Arc::new(RwLock::new(LruVerifierCache::new())),
			)
			.map_err(|_| libwallet::ErrorKind::Node)?;

			let mut state = self.state.lock();
			for input in tx.inputs() {
				// Output not unspent
				if !state.outputs.contains_key(&input.commit) {
					return Err(libwallet::ErrorKind::Node.into());
				}

				// Double spend attempt
				for tx_pending in state.pending.iter() {
					for in_pending in tx_pending.inputs() {
						if in_pending.commit == input.commit {
							return Err(libwallet::ErrorKind::Node.into());
						}
					}
				}
			}
			// Check for duplicate output
			for output in tx.outputs() {
				if state.outputs.contains_key(&output.commit) {
					return Err(libwallet::ErrorKind::Node.into());
				}

				for tx_pending in state.pending.iter() {
					for out_pending in tx_pending.outputs() {
						if out_pending.commit == output.commit {
							return Err(libwallet::ErrorKind::Node.into());
						}
					}
				}
			}
			// Check for duplicate kernel
			for kernel in tx.kernels() {
				// Duplicate kernel
				if state.kernels.contains_key(&kernel.excess) {
					return Err(libwallet::ErrorKind::Node.into());
				}

				for tx_pending in state.pending.iter() {
					for kernel_pending in tx_pending.kernels() {
						if kernel_pending.excess == kernel.excess {
							return Err(libwallet::ErrorKind::Node.into());
						}
					}
				}
			}
			state.pending.push(tx);

			Ok(())
		}
		fn get_version_info(&mut self) -> Option<libwallet::NodeVersionInfo> {
			unimplemented!()
		}
		fn get_chain_height(&self) -> Result<u64, libwallet::Error> {
			Ok(self.state.lock().height)
		}
		fn get_outputs_from_node(
			&self,
			wallet_outputs: Vec<Commitment>,
		) -> Result<HashMap<Commitment, (String, u64, u64)>, libwallet::Error> {
			let mut map = HashMap::new();
			let state = self.state.lock();
			for output in wallet_outputs {
				if let Some(height) = state.outputs.get(&output) {
					map.insert(output, (to_hex(output.0.to_vec()), *height, 0));
				}
			}
			Ok(map)
		}
		fn get_outputs_by_pmmr_index(
			&self,
			_start_height: u64,
			_max_outputs: u64,
		) -> Result<(u64, u64, Vec<(Commitment, RangeProof, bool, u64, u64)>), libwallet::Error> {
			unimplemented!()
		}
		fn get_kernel(
			&mut self,
			excess: &Commitment,
			_min_height: Option<u64>,
			_max_height: Option<u64>,
		) -> Result<Option<(TxKernel, u64, u64)>, libwallet::Error> {
			let state = self.state.lock();
			let res = state
				.kernels
				.get(excess)
				.map(|(kernel, height)| (kernel.clone(), *height, 0));
			Ok(res)
		}
	}

	#[test]
	fn test_refund_tx_lock() {
		set_test_mode(true);
		let kc_sell = keychain(1);
		let ctx_sell = context_sell(&kc_sell);
		let secondary_redeem_address = btc_address(&kc_sell);
		let height = 100_000;

		let mut api_sell = BtcSwapApi::new(TestNodeClient::new(height), TestBtcNodeClient::new(1));
		let (swap, _) = api_sell
			.create_swap_offer(
				&kc_sell,
				&ctx_sell,
				None,
				100 * GRIN_UNIT,
				3_000_000,
				Currency::Btc,
				secondary_redeem_address,
			)
			.unwrap();
		let message = api_sell.message(&kc_sell, &swap).unwrap();

		// Simulate short refund lock time by passing height+4h
		let kc_buy = keychain(2);
		let ctx_buy = context_buy(&kc_buy);
		let mut api_buy = BtcSwapApi::new(
			TestNodeClient::new(height + 4 * 60),
			TestBtcNodeClient::new(1),
		);
		let res = api_buy.accept_swap_offer(&kc_buy, &ctx_buy, None, message);
		assert_eq!(res.err().unwrap(), ErrorKind::InvalidLockHeightRefundTx); // Swap cannot be accepted
	}

	#[test]
	fn test_btc_swap() {
		set_test_mode(true);
		let write_json = false;

		let kc_sell = keychain(1);
		let ctx_sell = context_sell(&kc_sell);
		let secondary_redeem_address = btc_address(&kc_sell);

		let nc = TestNodeClient::new(300_000);
		let btc_nc = TestBtcNodeClient::new(500_000);

		let amount = 100 * GRIN_UNIT;
		let btc_amount_1 = 2_000_000;
		let btc_amount_2 = 1_000_000;
		let btc_amount = btc_amount_1 + btc_amount_2;

		// Seller: create swap offer
		let mut api_sell = BtcSwapApi::new(nc.clone(), btc_nc.clone());
		let (mut swap_sell, action) = api_sell
			.create_swap_offer(
				&kc_sell,
				&ctx_sell,
				None,
				amount,
				btc_amount,
				Currency::Btc,
				secondary_redeem_address,
			)
			.unwrap();
		assert_eq!(action, Action::SendMessage(1));
		assert_eq!(swap_sell.status, Status::Created);
		let message_1 = api_sell.message(&kc_sell, &swap_sell).unwrap();
		let action = api_sell
			.message_sent(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		assert_eq!(action, Action::ReceiveMessage);
		assert_eq!(swap_sell.status, Status::Offered);

		if write_json {
			write(
				"test/swap_sell_1.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();

			write(
				"test/message_1.json",
				serde_json::to_string_pretty(&message_1).unwrap(),
			)
			.unwrap();
			write(
				"test/context_sell.json",
				serde_json::to_string_pretty(&ctx_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("test/swap_sell_1.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
			assert_eq!(
				read_to_string("test/message_1.json").unwrap(),
				serde_json::to_string_pretty(&message_1).unwrap()
			);
			assert_eq!(
				read_to_string("test/context_sell.json").unwrap(),
				serde_json::to_string_pretty(&ctx_sell).unwrap()
			);
		}

		// Add inputs to utxo set
		nc.mine_blocks(2);
		for input in swap_sell.lock_slate.tx.inputs() {
			nc.push_output(input.commit.clone());
		}

		let kc_buy = keychain(2);
		let ctx_buy = context_buy(&kc_buy);

		// Buyer: accept swap offer
		let mut api_buy = BtcSwapApi::new(nc.clone(), btc_nc.clone());
		let (mut swap_buy, action) = api_buy
			.accept_swap_offer(&kc_buy, &ctx_buy, None, message_1)
			.unwrap();
		assert_eq!(swap_buy.status, Status::Offered);
		assert_eq!(action, Action::SendMessage(1));
		let message_2 = api_buy.message(&kc_buy, &swap_buy).unwrap();
		let action = api_buy
			.message_sent(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();

		// Buyer: should deposit bitcoin
		let address = match action {
			Action::DepositSecondary {
				currency: _,
				amount,
				address,
			} => {
				assert_eq!(amount, btc_amount);
				address
			}
			_ => panic!("Invalid action"),
		};
		assert_eq!(swap_buy.status, Status::Accepted);
		let address = Address::from_str(&address).unwrap();

		// Buyer: first deposit
		let tx_1 = BtcTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_1,
				script_pubkey: address.script_pubkey(),
			}],
		};
		let txid_1 = tx_1.txid();
		btc_nc.push_transaction(&tx_1);

		match api_buy
			.required_action(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap()
		{
			Action::DepositSecondary {
				currency: _,
				amount,
				address: _,
			} => assert_eq!(amount, btc_amount_2),
			_ => panic!("Invalid action"),
		};

		// Buyer: second deposit
		btc_nc.mine_blocks(2);
		let tx_2 = BtcTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_2,
				script_pubkey: address.script_pubkey(),
			}],
		};
		let txid_2 = tx_2.txid();
		btc_nc.push_transaction(&tx_2);
		match api_buy
			.required_action(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap()
		{
			Action::ConfirmationsSecondary {
				currency: _,
				required: _,
				actual,
			} => assert_eq!(actual, 1),
			_ => panic!("Invalid action"),
		};
		btc_nc.mine_blocks(5);

		// Buyer: wait for Grin confirmations
		match api_buy
			.required_action(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap()
		{
			Action::Confirmations {
				required: _,
				actual,
			} => assert_eq!(actual, 0),
			_ => panic!("Invalid action"),
		};

		// Check if buyer has correct confirmed outputs
		{
			let btc_data = swap_buy.secondary_data.unwrap_btc().unwrap();
			assert_eq!(btc_data.confirmed_outputs.len(), 2);
			let mut match_1 = 0;
			let mut match_2 = 0;
			for output in &btc_data.confirmed_outputs {
				if output.out_point.txid == txid_1 {
					match_1 += 1;
				}
				if output.out_point.txid == txid_2 {
					match_2 += 1;
				}
			}
			assert_eq!(match_1, 1);
			assert_eq!(match_2, 1);
		}

		if write_json {
			write(
				"test/swap_buy_1.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
			write(
				"test/message_2.json",
				serde_json::to_string_pretty(&message_2).unwrap(),
			)
			.unwrap();
			write(
				"test/context_buy.json",
				serde_json::to_string_pretty(&ctx_buy).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("test/swap_buy_1.json").unwrap(),
				serde_json::to_string_pretty(&swap_buy).unwrap()
			);
			assert_eq!(
				read_to_string("test/message_2.json").unwrap(),
				serde_json::to_string_pretty(&message_2).unwrap()
			);
			assert_eq!(
				read_to_string("test/context_buy.json").unwrap(),
				serde_json::to_string_pretty(&ctx_buy).unwrap()
			);
		}

		// Seller: receive accepted offer
		let action = api_sell
			.receive_message(&kc_sell, &mut swap_sell, &ctx_sell, message_2)
			.unwrap();
		assert_eq!(action, Action::PublishTx);
		assert_eq!(swap_sell.status, Status::Accepted);
		let action = api_sell
			.publish_transaction(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		match action {
			Action::Confirmations {
				required: _,
				actual,
			} => assert_eq!(actual, 0),
			_ => panic!("Invalid action"),
		}

		if write_json {
			write(
				"test/swap_sell_2.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("test/swap_sell_2.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		// Seller: wait for Grin confirmations
		nc.mine_blocks(10);
		match api_sell
			.required_action(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap()
		{
			Action::Confirmations {
				required: _,
				actual,
			} => assert_eq!(actual, 10),
			_ => panic!("Invalid action"),
		}

		// Buyer: wait for less Grin confirmations
		match api_buy
			.required_action(&kc_sell, &mut swap_buy, &ctx_buy)
			.unwrap()
		{
			Action::Confirmations {
				required: _,
				actual,
			} => assert_eq!(actual, 10),
			_ => panic!("Invalid action"),
		}

		// Undo a BTC block to test seller
		{
			let mut state = btc_nc.state.lock();
			state.height -= 1;
		}

		// Seller: wait BTC confirmations
		nc.mine_blocks(20);
		match api_sell
			.required_action(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap()
		{
			Action::ConfirmationsSecondary {
				currency: _,
				required: _,
				actual,
			} => assert_eq!(actual, 5),
			_ => panic!("Invalid action"),
		}
		btc_nc.mine_block();

		if write_json {
			write(
				"test/swap_sell_3.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("test/swap_sell_3.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		// Buyer: start redeem
		let action = api_buy
			.required_action(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();
		assert_eq!(action, Action::SendMessage(2));
		assert_eq!(swap_buy.status, Status::Locked);
		let message_3 = api_buy.message(&kc_buy, &swap_buy).unwrap();
		api_buy
			.message_sent(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();

		if write_json {
			write(
				"test/swap_buy_2.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
			write(
				"test/message_3.json",
				serde_json::to_string_pretty(&message_3).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("test/swap_buy_2.json").unwrap(),
				serde_json::to_string_pretty(&swap_buy).unwrap()
			);
			assert_eq!(
				read_to_string("test/message_3.json").unwrap(),
				serde_json::to_string_pretty(&message_3).unwrap()
			);
		}

		// Seller: sign redeem
		let action = api_sell
			.required_action(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		assert_eq!(action, Action::ReceiveMessage);
		assert_eq!(swap_sell.status, Status::Locked);
		let action = api_sell
			.receive_message(&kc_sell, &mut swap_sell, &ctx_sell, message_3)
			.unwrap();
		assert_eq!(action, Action::SendMessage(2));
		assert_eq!(swap_sell.status, Status::InitRedeem);
		let message_4 = api_sell.message(&kc_sell, &swap_sell).unwrap();
		let action = api_sell
			.message_sent(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();

		// Seller: wait for buyer's on-chain redeem tx
		assert_eq!(action, Action::ConfirmationRedeem);
		assert_eq!(swap_sell.status, Status::Redeem);

		if write_json {
			write(
				"test/swap_sell_4.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
			write(
				"test/message_4.json",
				serde_json::to_string_pretty(&message_4).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("test/swap_sell_4.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
			assert_eq!(
				read_to_string("test/message_4.json").unwrap(),
				serde_json::to_string_pretty(&message_4).unwrap()
			);
		}

		// Buyer: redeem
		let action = api_buy
			.required_action(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();
		assert_eq!(action, Action::ReceiveMessage);
		assert_eq!(swap_buy.status, Status::InitRedeem);
		let action = api_buy
			.receive_message(&kc_buy, &mut swap_buy, &ctx_buy, message_4)
			.unwrap();
		assert_eq!(action, Action::PublishTx);
		assert_eq!(swap_buy.status, Status::Redeem);
		let action = api_buy
			.publish_transaction(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();
		assert_eq!(action, Action::ConfirmationRedeem);

		// Buyer: complete!
		nc.mine_block();
		let action = api_buy
			.required_action(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();
		assert_eq!(action, Action::Complete);
		// At this point, buyer would add Grin to their outputs
		let action = api_buy.completed(&kc_buy, &mut swap_buy, &ctx_buy).unwrap();
		assert_eq!(action, Action::None);
		assert_eq!(swap_buy.status, Status::Completed);

		if write_json {
			write(
				"test/swap_buy_3.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("test/swap_buy_3.json").unwrap(),
				serde_json::to_string_pretty(&swap_buy).unwrap()
			);
		}

		// Seller: publish BTC tx
		let action = api_sell
			.required_action(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		assert_eq!(action, Action::PublishTxSecondary(Currency::Btc));
		assert_eq!(swap_sell.status, Status::RedeemSecondary);

		if write_json {
			write(
				"test/swap_sell_5.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("test/swap_sell_5.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		// Seller: wait for BTC confirmations
		let action = api_sell
			.publish_secondary_transaction(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		match action {
			Action::ConfirmationRedeemSecondary(_, _) => {}
			_ => panic!("Invalid action"),
		};

		// Seller: complete!
		btc_nc.mine_block();
		let action = api_sell
			.required_action(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		assert_eq!(action, Action::Complete);
		let action = api_sell
			.completed(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		assert_eq!(action, Action::None);
		assert_eq!(swap_sell.status, Status::Completed);

		if write_json {
			write(
				"test/swap_sell_6.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("test/swap_sell_6.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		assert!(!write_json, "json files written");
	}

	#[test]
	fn test_swap_serde() {
		// Seller context
		let ctx_sell_str = read_to_string("test/context_sell.json").unwrap();
		let ctx_sell: Context = serde_json::from_str(&ctx_sell_str).unwrap();
		assert_eq!(
			serde_json::to_string_pretty(&ctx_sell).unwrap(),
			ctx_sell_str
		);

		// Buyer context
		let ctx_buy_str = read_to_string("test/context_buy.json").unwrap();
		let ctx_buy: Context = serde_json::from_str(&ctx_buy_str).unwrap();
		assert_eq!(serde_json::to_string_pretty(&ctx_buy).unwrap(), ctx_buy_str);

		// Seller's swap state in different stages
		for i in 0..6 {
			println!("TRY SELL {}", i);
			let swap_str = read_to_string(format!("test/swap_sell_{}.json", i + 1)).unwrap();
			let swap: Swap = serde_json::from_str(&swap_str).unwrap();
			assert_eq!(serde_json::to_string_pretty(&swap).unwrap(), swap_str);
			println!("OK SELL {}", i);
		}

		// Buyer's swap state in different stages
		for i in 0..3 {
			println!("TRY BUY {}", i);
			let swap_str = read_to_string(format!("test/swap_buy_{}.json", i + 1)).unwrap();
			let swap: Swap = serde_json::from_str(&swap_str).unwrap();
			assert_eq!(serde_json::to_string_pretty(&swap).unwrap(), swap_str);
			println!("OK BUY {}", i);
		}

		// Messages
		for i in 0..4 {
			println!("TRY MSG {}", i);
			let message_str = read_to_string(format!("test/message_{}.json", i + 1)).unwrap();
			let message: Message = serde_json::from_str(&message_str).unwrap();
			assert_eq!(serde_json::to_string_pretty(&message).unwrap(), message_str);
			println!("OK MSG {}", i);
		}
	}
}
