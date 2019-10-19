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

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate blake2_rfc as blake2;
extern crate byteorder;
extern crate failure;
extern crate grin_core;
extern crate grin_keychain;
extern crate grin_util;
extern crate grin_wallet_libwallet as libwallet;
extern crate hex;
#[macro_use]
extern crate lazy_static;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sha2;
extern crate uuid;

pub use swap::api::SwapApi;
pub use swap::bitcoin::{BtcNodeClient, BtcSwapApi, ElectrumNodeClient, TestBtcNodeClient};
pub use swap::message::{Message, OfferUpdate, SecondaryUpdate, Update};
pub use swap::multisig::Builder;
pub use swap::types::{Action, BuyerContext, Context, Currency, Role, SellerContext, Status};
pub use swap::{is_test_mode, set_test_mode, ErrorKind, Keychain, Swap};

mod swap;
