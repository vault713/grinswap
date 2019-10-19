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

use super::multisig;
use super::types::Status;
use failure::Fail;
use grin_core::core::committed;
use grin_util::secp;
use libwallet;
use std::io;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	#[fail(display = "Missing keychain")]
	MissingKeychain,
	#[fail(display = "Unexpected action")]
	UnexpectedAction,
	#[fail(display = "Unexpected network")]
	UnexpectedNetwork,
	#[fail(display = "Unexpected role")]
	UnexpectedRole,
	#[fail(display = "Unexpected status. Expected: {:?}, actual: {:?}", _0, _1)]
	UnexpectedStatus(Status, Status),
	#[fail(display = "Insufficient funds. Required: {}, available: {}", _0, _1)]
	InsufficientFunds(u64, u64),
	#[fail(display = "Unexpected message type")]
	UnexpectedMessageType,
	#[fail(display = "Unexpected secondary coin type")]
	UnexpectedCoinType,
	#[fail(display = "Version incompatibility")]
	IncompatibleVersion,
	#[fail(display = "Mismatch between swap and message IDs")]
	MismatchedId,
	#[fail(display = "Invalid amount string")]
	InvalidAmountString,
	#[fail(display = "Invalid currency")]
	InvalidCurrency,
	#[fail(display = "Invalid lock height for lock tx")]
	InvalidLockHeightLockTx,
	#[fail(display = "Invalid lock height for refund tx")]
	InvalidLockHeightRefundTx,
	#[fail(display = "Invalid lock for secondary currency")]
	InvalidLockSecondary,
	#[fail(display = "Invalid adaptor signature")]
	InvalidAdaptorSignature,
	#[fail(display = "Secondary currency data complete")]
	SecondaryDataIncomplete,
	#[fail(display = "This function should only be called once")]
	OneShot,
	#[fail(display = "Swap is already finalized")]
	Finalized,
	#[fail(display = "{}", _0)]
	Multisig(multisig::ErrorKind),
	#[fail(display = "{}", _0)]
	Keychain(grin_keychain::Error),
	#[fail(display = "{}", _0)]
	LibWallet(libwallet::ErrorKind),
	#[fail(display = "{}", _0)]
	Secp(secp::Error),
	#[fail(display = "I/O: {}", _0)]
	IO(String),
	#[fail(display = "Serde error")]
	Serde,
	#[fail(display = "Rpc: {}", _0)]
	Rpc(&'static str),
	#[fail(display = "{}", _0)]
	NodeClient(String),
	#[fail(display = "{}", _0)]
	GenericNetwork(String),
	#[fail(display = "{}", _0)]
	Generic(String),
}

impl ErrorKind {
	pub fn is_network_error(&self) -> bool {
		use ErrorKind::*;
		format!("");
		match self {
			Rpc(_) | NodeClient(_) | LibWallet(libwallet::ErrorKind::Node) | GenericNetwork(_) => {
				true
			}
			_ => false,
		}
	}
}

impl From<grin_keychain::Error> for ErrorKind {
	fn from(error: grin_keychain::Error) -> ErrorKind {
		ErrorKind::Keychain(error)
	}
}

impl From<multisig::ErrorKind> for ErrorKind {
	fn from(error: multisig::ErrorKind) -> ErrorKind {
		ErrorKind::Multisig(error)
	}
}

impl From<libwallet::Error> for ErrorKind {
	fn from(error: libwallet::Error) -> ErrorKind {
		ErrorKind::LibWallet(error.kind())
	}
}

impl From<secp::Error> for ErrorKind {
	fn from(error: secp::Error) -> ErrorKind {
		ErrorKind::Secp(error)
	}
}

impl From<io::Error> for ErrorKind {
	fn from(error: io::Error) -> ErrorKind {
		ErrorKind::IO(format!("{}", error))
	}
}

impl From<serde_json::Error> for ErrorKind {
	fn from(_error: serde_json::Error) -> ErrorKind {
		ErrorKind::Serde
	}
}

impl From<committed::Error> for ErrorKind {
	fn from(error: committed::Error) -> ErrorKind {
		match error {
			committed::Error::Keychain(e) => e.into(),
			committed::Error::Secp(e) => e.into(),
			e => ErrorKind::Generic(format!("{}", e)),
		}
	}
}

#[macro_export]
macro_rules! generic {
    ($($arg:tt)*) => ($crate::ErrorKind::Generic(format!($($arg)*)))
}

#[macro_export]
macro_rules! network {
    ($($arg:tt)*) => ($crate::ErrorKind::GenericNetwork(format!($($arg)*)))
}
