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

use failure::Fail;
use grin_util::secp;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	#[fail(display = "Invalid reveal")]
	Reveal,
	#[fail(display = "Invalid hash length")]
	HashLength,
	#[fail(display = "Participant already exists")]
	ParticipantExists,
	#[fail(display = "Participant doesn't exist")]
	ParticipantDoesntExist,
	#[fail(display = "Participant created in the wrong order")]
	ParticipantOrdering,
	#[fail(display = "Participant invalid")]
	ParticipantInvalid,
	#[fail(display = "Multisig incomplete")]
	MultiSigIncomplete,
	#[fail(display = "Common nonce missing")]
	CommonNonceMissing,
	#[fail(display = "Round 1 missing field")]
	Round1Missing,
	#[fail(display = "Round 2 missing field")]
	Round2Missing,
	#[fail(display = "Secp: _0")]
	Secp(secp::Error),
}

impl From<secp::Error> for ErrorKind {
	fn from(error: secp::Error) -> ErrorKind {
		ErrorKind::Secp(error)
	}
}
