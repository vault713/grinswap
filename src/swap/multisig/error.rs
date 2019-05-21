use failure::Fail;

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
    #[fail(display = "Multisig incomplete")]
    MultiSigIncomplete,
    #[fail(display = "Round 1 missing field")]
    Round1Missing,
    #[fail(display = "Round 2 missing field")]
    Round2Missing,
}