//! Backends providing platform-specific low-level functionality.
//!
//! As this crate is designed to be usable on any platform, it cannot rely on a specific data
//! storage and cryptography implementation.  Instead, a [`Card`][`crate::Card`] has to be provided
//! with a [`Backend`] implementation that provides these operations.

#[cfg(feature = "backend-software")]
mod software;
#[cfg(feature = "backend-trussed")]
mod trussed;

#[cfg(feature = "backend-trussed")]
pub use self::trussed::TrussedBackend;
#[cfg(feature = "backend-software")]
pub use software::SoftwareBackend;

use core::fmt::Debug;

/// A backend that provides data storage and cryptography operations.
pub trait Backend: Debug {
    /// Checks whether the given value matches the pin of the given type.
    fn verify_pin(&self, pin: Pin, value: &[u8]) -> bool;
}

/// Dummy backend.
///
/// This backend can be used to compile code without relying on a proper [`Backend`]
/// implementation.  All calls to its methods panic.
#[derive(Clone, Copy, Debug)]
pub struct DummyBackend;

impl Backend for DummyBackend {
    fn verify_pin(&self, _pin: Pin, _value: &[u8]) -> bool {
        unreachable!();
    }
}

/// The available PIN types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pin {
    /// The user PIN.
    UserPin,
    /// The admin PIN.
    AdminPin,
}
