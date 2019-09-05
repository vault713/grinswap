use super::bitcoin::BtcUpdate;
use super::multisig::ParticipantData as MultisigParticipant;
use super::ser::*;
use super::types::{Currency, Network};
use super::ErrorKind;
use grin_core::libtx::secp_ser;
use grin_util::secp::key::PublicKey;
use grin_util::secp::Signature;
use libwallet::{ParticipantData as TxParticipant, VersionedSlate};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct Message {
	pub id: Uuid,
	pub inner: Update,
	inner_secondary: SecondaryUpdate,
}

impl Message {
	pub fn new(id: Uuid, inner: Update, inner_secondary: SecondaryUpdate) -> Self {
		Self {
			id,
			inner,
			inner_secondary,
		}
	}

	pub fn set_inner_secondary(&mut self, inner_secondary: SecondaryUpdate) {
		self.inner_secondary = inner_secondary;
	}

	pub fn unwrap_offer(self) -> Result<(Uuid, OfferUpdate, SecondaryUpdate), ErrorKind> {
		match self.inner {
			Update::Offer(u) => Ok((self.id, u, self.inner_secondary)),
			_ => Err(ErrorKind::UnexpectedMessageType),
		}
	}

	pub fn unwrap_accept_offer(
		self,
	) -> Result<(Uuid, AcceptOfferUpdate, SecondaryUpdate), ErrorKind> {
		match self.inner {
			Update::AcceptOffer(u) => Ok((self.id, u, self.inner_secondary)),
			_ => Err(ErrorKind::UnexpectedMessageType),
		}
	}

	pub fn unwrap_init_redeem(
		self,
	) -> Result<(Uuid, InitRedeemUpdate, SecondaryUpdate), ErrorKind> {
		match self.inner {
			Update::InitRedeem(u) => Ok((self.id, u, self.inner_secondary)),
			_ => Err(ErrorKind::UnexpectedMessageType),
		}
	}

	pub fn unwrap_redeem(self) -> Result<(Uuid, RedeemUpdate, SecondaryUpdate), ErrorKind> {
		match self.inner {
			Update::Redeem(u) => Ok((self.id, u, self.inner_secondary)),
			_ => Err(ErrorKind::UnexpectedMessageType),
		}
	}
}

#[derive(Serialize, Deserialize)]
pub enum Update {
	None,
	Offer(OfferUpdate),
	AcceptOffer(AcceptOfferUpdate),
	InitRedeem(InitRedeemUpdate),
	Redeem(RedeemUpdate),
}

#[derive(Serialize, Deserialize)]
pub struct OfferUpdate {
	pub version: u8,
	pub network: Network,
	#[serde(with = "secp_ser::string_or_u64")]
	pub primary_amount: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub secondary_amount: u64,
	pub secondary_currency: Currency,
	pub multisig: MultisigParticipant,
	pub lock_slate: VersionedSlate,
	pub refund_slate: VersionedSlate,
	pub redeem_participant: TxParticipant,
}

#[derive(Serialize, Deserialize)]
pub struct AcceptOfferUpdate {
	pub multisig: MultisigParticipant,
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub redeem_public: PublicKey,
	pub lock_participant: TxParticipant,
	pub refund_participant: TxParticipant,
}

#[derive(Serialize, Deserialize)]
pub struct InitRedeemUpdate {
	pub redeem_slate: VersionedSlate,
	#[serde(serialize_with = "sig_to_hex", deserialize_with = "sig_from_hex")]
	pub adaptor_signature: Signature,
}

#[derive(Serialize, Deserialize)]
pub struct RedeemUpdate {
	pub redeem_participant: TxParticipant,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecondaryUpdate {
	Empty,
	BTC(BtcUpdate),
}

impl SecondaryUpdate {
	pub fn unwrap_btc(self) -> Result<BtcUpdate, ErrorKind> {
		match self {
			SecondaryUpdate::BTC(d) => Ok(d),
			_ => Err(ErrorKind::UnexpectedCoinType),
		}
	}
}
