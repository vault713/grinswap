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
