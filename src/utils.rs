// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

// This is a re-implementation of the Result::inspect_err method that is currently only available
// in nightly Rust.  Once it is stablizied, we should remove this trait.
pub trait InspectErr<E>: Sized {
    fn inspect_err_stable<F: FnOnce(&E)>(self, f: F) -> Self;
}

impl<T, E> InspectErr<E> for Result<T, E> {
    fn inspect_err_stable<F: FnOnce(&E)>(self, f: F) -> Self {
        if let Self::Err(e) = &self {
            f(e);
        }
        self
    }
}
