// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! Virtual trussed client (mostly for testing)

/// Implementation of ExtensionDispatch for a virtual implementation of opcard
pub mod dispatch {

    use trussed::{
        api::{reply, request, Reply, Request},
        backend::{Backend as _, BackendId},
        error::Error,
        platform::Platform,
        serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl as _},
        service::ServiceResources,
        types::{Bytes, Context, Location},
    };
    use trussed_auth::{AuthBackend, AuthContext, AuthExtension, MAX_HW_KEY_LEN};
    use trussed_staging::{
        wrap_key_to_file::WrapKeyToFileExtension, StagingBackend, StagingContext,
    };

    #[cfg(feature = "rsa")]
    use trussed_rsa_alloc::SoftwareRsa;

    /// Backends used by opcard
    pub const BACKENDS: &[BackendId<Backend>] = &[
        BackendId::Custom(Backend::Staging),
        BackendId::Custom(Backend::Auth),
        #[cfg(feature = "rsa")]
        BackendId::Custom(Backend::Rsa),
        BackendId::Core,
    ];

    /// Id for the ExtensionDispatch implementation
    #[derive(Debug, Clone, Copy)]
    pub enum Backend {
        /// trussed-auth
        Auth,
        /// trussed-staging
        Staging,
        /// trussed-rsa-alloc
        #[cfg(feature = "rsa")]
        Rsa,
    }

    /// Extensions used by opcard
    /// Used for the ExtensionDispatch implementation
    #[derive(Debug, Clone, Copy)]
    pub enum Extension {
        /// trussed-auth
        Auth,
        /// wrap_key_to_file
        WrapKeyToFile,
    }

    impl From<Extension> for u8 {
        fn from(extension: Extension) -> Self {
            match extension {
                Extension::Auth => 0,
                Extension::WrapKeyToFile => 1,
            }
        }
    }

    impl TryFrom<u8> for Extension {
        type Error = Error;

        fn try_from(id: u8) -> Result<Self, Self::Error> {
            match id {
                0 => Ok(Extension::Auth),
                1 => Ok(Extension::WrapKeyToFile),
                _ => Err(Error::InternalError),
            }
        }
    }

    /// Dispatch implementation with the backends required by opcard
    #[derive(Debug)]
    pub struct Dispatch {
        auth: AuthBackend,
        staging: StagingBackend,
    }

    /// Dispatch context for the backends required by opcard
    #[derive(Default, Debug)]
    pub struct DispatchContext {
        auth: AuthContext,
        staging: StagingContext,
    }

    impl Dispatch {
        /// Create a new dispatch using the internal filesystem
        pub fn new() -> Self {
            Self {
                auth: AuthBackend::new(Location::Internal),
                staging: StagingBackend::new(),
            }
        }

        /// Create a new dispatch using the internal filesystem and a key derived from hardware parameters
        pub fn with_hw_key(hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
            Self {
                auth: AuthBackend::with_hw_key(Location::Internal, hw_key),
                staging: StagingBackend::new(),
            }
        }
    }

    impl Default for Dispatch {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ExtensionDispatch for Dispatch {
        type BackendId = Backend;
        type Context = DispatchContext;
        type ExtensionId = Extension;

        fn core_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            ctx: &mut Context<Self::Context>,
            request: &Request,
            resources: &mut ServiceResources<P>,
        ) -> Result<Reply, Error> {
            match backend {
                Backend::Auth => {
                    self.auth
                        .request(&mut ctx.core, &mut ctx.backends.auth, request, resources)
                }
                Backend::Staging => self.staging.request(
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
                #[cfg(feature = "rsa")]
                Backend::Rsa => SoftwareRsa.request(&mut ctx.core, &mut (), request, resources),
            }
        }

        fn extension_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            extension: &Self::ExtensionId,
            ctx: &mut Context<Self::Context>,
            request: &request::SerdeExtension,
            resources: &mut ServiceResources<P>,
        ) -> Result<reply::SerdeExtension, Error> {
            match backend {
                Backend::Auth => match extension {
                    Extension::Auth => self.auth.extension_request_serialized(
                        &mut ctx.core,
                        &mut ctx.backends.auth,
                        request,
                        resources,
                    ),
                    Extension::WrapKeyToFile => Err(Error::RequestNotAvailable),
                },
                Backend::Staging => match extension {
                    Extension::WrapKeyToFile => self.staging.extension_request_serialized(
                        &mut ctx.core,
                        &mut ctx.backends.staging,
                        request,
                        resources,
                    ),
                    Extension::Auth => Err(Error::RequestNotAvailable),
                },

                #[cfg(feature = "rsa")]
                Backend::Rsa => Err(Error::RequestNotAvailable),
            }
        }
    }

    impl ExtensionId<AuthExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Auth;
    }

    impl ExtensionId<WrapKeyToFileExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::WrapKeyToFile;
    }
}

use std::path::PathBuf;
use trussed::{
    types::Bytes,
    virt::{self, Client, Filesystem, Ram, StoreProvider},
};

/// Client type using a dispatcher with the backends required by opcard
pub type VirtClient<S> = Client<S, dispatch::Dispatch>;

/// Run a client using a provided store
pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<S>) -> R,
    S: StoreProvider,
{
    #[allow(clippy::unwrap_used)]
    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            dispatch::Dispatch::with_hw_key(Bytes::from_slice(b"some bytes").unwrap()),
            dispatch::BACKENDS,
            f,
        )
    })
}

/// Run the backend with the extensions required by opcard
/// using storage backed by a file
pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<Filesystem>) -> R,
    P: Into<PathBuf>,
{
    with_client(Filesystem::new(internal), client_id, f)
}

/// Run the backend with the extensions required by opcard
/// using a RAM file storage
pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<Ram>) -> R,
{
    with_client(Ram::default(), client_id, f)
}
