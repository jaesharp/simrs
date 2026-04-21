//! Test-only `JavaCard` control-plane applet + composable
//! [`Transport`](simrs_transport::Transport) wrapper.
//!
//! Read the design doc at
//! [`docs/architecture/controlplane-applet.md`](../../../docs/architecture/controlplane-applet.md)
//! for the full surface, rollout plan, and security considerations.
//!
//! # Usage shape
//!
//! Wrap any [`Transport`](simrs_transport::Transport) with
//! [`ControlplaneCard::new`](card::ControlplaneCard::new) to interpose
//! the control plane. SELECT [`CONTROLPLANE_AID`](aid::CONTROLPLANE_AID)
//! to switch context; `80 F0 <P1> <P2>` commands after that land in
//! the applet until another AID is SELECT'd.
//!
//! This crate is test-only (`publish = false`, reserved AID) and
//! introduces no production-code surface: existing
//! [`Transport`](simrs_transport::Transport) implementations do not
//! need to know about the control plane at all.
//!
//! # Phase A -- scaffolding
//!
//! Currently implemented:
//!
//! - AID constants ([`aid`]).
//! - Protocol constants and the
//!   [`Category`](protocol::Category) enum ([`protocol`]).
//! - Applet dispatcher ([`ControlplaneApplet`](applet::ControlplaneApplet))
//!   with the [`Misc`](protocol::Category::Misc) category
//!   (ping + version).
//! - Composable card wrapper
//!   ([`ControlplaneCard`](card::ControlplaneCard)) that intercepts
//!   SELECT + routes subsequent APDUs while selected.
//!
//! Remaining probes (JCVM state, heap, fault injection, PRNG,
//! snapshot, firewall, interposer) are scaffolded as
//! [`Category`](protocol::Category) variants but dispatch returns
//! `6A 86` until their handlers land. See the design doc for the
//! phased rollout.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod aid;
pub mod applet;
pub mod capability;
pub mod card;
pub mod probes;
pub mod protocol;
pub mod timing_domain;

pub use aid::{CONTROLPLANE_AID, CONTROLPLANE_PACKAGE_AID, is_controlplane_aid};
pub use applet::{AppletState, ControlplaneApplet};
pub use card::ControlplaneCard;
pub use protocol::{CLA, Category, INS};
