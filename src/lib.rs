//! This crate implements the [OpenPGP smart card specification v3.4][spec].
//!
//! [spec]: https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf
//!
//! # Backends
//!
//! This crate is designed to work on any platform.  Therefore, it requires a
//! [`Backend`][`backend::Backend`] implementation that provides platform-specific low-level
//! functionality like storing data and performing cryptographic operations.  These functions can
//! be provided by software or hardware.  `opcard` provides these `Backend` implementations:
//!
//! - [`SoftwareBackend`][`backend::SoftwareBackend`] uses the filesystem to store data (requires
//!   the `backend-software` feature).
//! - [`TrussedBackend`][`backend::TrussedBackend`] uses a [Trussed](https://trussed.dev/) client
//!   (requires the `backend-trussed` feature).
//! - [`DummyBackend`][`backend::DummyBackend`] always panics and can be used to compile code
//!   without using a proper `Backend` implementation.
//!
//! # Command handling
//!
//! The [`Card`] struct is the main entry point for this crate.  It depends on a
//! [`Backend`][`backend::Backend`] implementation that provides low-level functionality.  The card
//! can be configured using [`Options`].  Its [`Card::handle`] method expects a full APDU command
//! and constructs a reply for it.
//!
//! # APDU dispatch
//!
//! The APDU dispatch has to be implemented by the user of this crate.  There are some mechanisms
//! that make this easier:
//!
//! - If the `apdu-dispatch` feature is enabled, [`Card`] implements the `apdu_dispatch::App`
//!   trait and can be used with `apdu_dispatch`.
//! - If the `virtual` feature is enabled, [`VirtualCard`] can be used to emulate a smart card
//!   using [`vsmartcard`](https://frankmorgner.github.io/vsmartcard/) and `vpicc-rs`.

#![cfg_attr(no_std, not(feature = "std"))]
#![warn(
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    non_ascii_idents,
    trivial_casts,
    unused,
    unused_qualifications,
    clippy::expect_used,
    clippy::unwrap_used
)]
#![deny(unsafe_code)]

pub mod backend;
mod card;
mod command;
#[cfg(feature = "virtual")]
mod vpicc;

#[cfg(feature = "virtual")]
pub use self::vpicc::VirtualCard;
pub use card::{Card, Options};
