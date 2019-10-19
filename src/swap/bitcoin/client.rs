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

use crate::swap::ErrorKind;
use bitcoin::consensus::Decodable;
use bitcoin::{Address, OutPoint, Transaction};
use bitcoin_hashes::sha256d;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::mem;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone, Eq)]
pub struct Output {
	#[serde(with = "OutPointRef")]
	pub out_point: OutPoint,
	pub value: u64,
	pub height: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(remote = "OutPoint")]
struct OutPointRef {
	pub txid: sha256d::Hash,
	pub vout: u32,
}

impl PartialEq for Output {
	fn eq(&self, other: &Output) -> bool {
		self.out_point == other.out_point
	}
}

impl Hash for Output {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.out_point.hash(state);
	}
}

pub trait BtcNodeClient: Sync + Send + 'static {
	fn height(&mut self) -> Result<u64, ErrorKind>;
	fn unspent(&mut self, address: &Address) -> Result<Vec<Output>, ErrorKind>;
	fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), ErrorKind>;
	fn transaction(
		&mut self,
		tx_hash: &sha256d::Hash,
	) -> Result<Option<(Option<u64>, Transaction)>, ErrorKind>;
}

#[derive(Debug, Clone)]
pub struct TestBtcNodeClientState {
	pub height: u64,
	pub tx_heights: HashMap<sha256d::Hash, u64>,
	pub txs: HashMap<sha256d::Hash, Transaction>,
	pub pending: HashMap<sha256d::Hash, Transaction>,
}

#[derive(Debug, Clone)]
pub struct TestBtcNodeClient {
	pub state: Arc<Mutex<TestBtcNodeClientState>>,
}

impl TestBtcNodeClient {
	pub fn new(height: u64) -> Self {
		Self {
			state: Arc::new(Mutex::new(TestBtcNodeClientState {
				height,
				tx_heights: HashMap::new(),
				txs: HashMap::new(),
				pending: HashMap::new(),
			})),
		}
	}

	pub fn push_transaction(&self, transaction: &Transaction) {
		let mut state = self.state.lock();
		let height = state.height;

		let txid = transaction.txid();
		state.tx_heights.insert(txid.clone(), height);
		state.txs.insert(txid, transaction.clone());
	}

	pub fn mine_block(&self) {
		let mut state = self.state.lock();
		state.height += 1;
		let height = state.height;

		let pending = mem::replace(&mut state.pending, HashMap::new());
		for (txid, tx) in pending {
			state.tx_heights.insert(txid.clone(), height);
			state.txs.insert(txid, tx);
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

impl BtcNodeClient for TestBtcNodeClient {
	fn height(&mut self) -> Result<u64, ErrorKind> {
		Ok(self.state.lock().height)
	}

	fn unspent(&mut self, address: &Address) -> Result<Vec<Output>, ErrorKind> {
		let state = self.state.lock();
		let script_pubkey = address.script_pubkey();

		let mut outputs = Vec::new();
		for (txid, tx) in &state.txs {
			let height = *state.tx_heights.get(txid).unwrap();
			for idx in 0..tx.output.len() {
				let o = &tx.output[idx];
				if o.script_pubkey == script_pubkey {
					outputs.push(Output {
						out_point: OutPoint {
							txid: txid.clone(),
							vout: idx as u32,
						},
						value: o.value,
						height,
					});
				}
			}
		}

		Ok(outputs)
	}

	fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), ErrorKind> {
		let mut state = self.state.lock();

		let cursor = Cursor::new(tx);
		let tx = Transaction::consensus_decode(cursor)
			.map_err(|_| ErrorKind::NodeClient("Unable to parse transaction".into()))?;

		let txid = tx.txid();
		if state.pending.contains_key(&txid) {
			return Err(ErrorKind::NodeClient("Already in mempool".into()));
		}
		if state.txs.contains_key(&txid) {
			return Err(ErrorKind::NodeClient("Already in chain".into()));
		}

		tx.verify(&state.txs)
			.map_err(|e| ErrorKind::NodeClient(format!("{}", e)))?;
		state.pending.insert(txid, tx.clone());

		Ok(())
	}

	fn transaction(
		&mut self,
		tx_hash: &sha256d::Hash,
	) -> Result<Option<(Option<u64>, Transaction)>, ErrorKind> {
		let state = self.state.lock();

		if let Some(tx) = state.pending.get(tx_hash) {
			return Ok(Some((None, tx.clone())));
		}

		let tx = state
			.txs
			.get(tx_hash)
			.map(|t| (state.tx_heights.get(tx_hash).map(|h| *h), t.clone()));

		Ok(tx)
	}
}
