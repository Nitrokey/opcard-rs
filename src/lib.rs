// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! This crate implements the [OpenPGP smart card specification v3.4][spec].
//!
//! [spec]: https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf
//!
//! # Backends
//!
//! This crate is designed to work on any platform supported by [trussed](https://trussed.dev).
//! Trussed requires a [Client][trussed::Client] implementation for each platform.
//!
//! # Command handling
//!
//! The [`Card`] struct is the main entry point for this crate.  It depends on a Trussed
//! [`Client`][`trussed::Client`] implementation that provides low-level functionality.  The card
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
//! - If the `vpicc` feature is enabled, [`VpiccCard`] can be used to emulate a smart card
//!   using [`vsmartcard`](https://frankmorgner.github.io/vsmartcard/) and `vpicc-rs`.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
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

#[cfg(not(feature = "delog"))]
#[macro_use]
extern crate log;

#[cfg(feature = "delog")]
delog::generate_macros!();

mod backend;
mod card;
mod command;
mod error;
mod state;
mod tlv;
mod types;
mod utils;
#[cfg(feature = "vpicc")]
mod vpicc;

#[cfg(feature = "virt")]
pub mod virt;

#[cfg(feature = "vpicc")]
pub use self::vpicc::VpiccCard;
pub use card::{Card, Options};
pub use state::{DEFAULT_ADMIN_PIN, DEFAULT_USER_PIN};
