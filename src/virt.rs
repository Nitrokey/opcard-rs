// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! Virtual trussed client (mostly for testing)

/// Implementation of ExtensionDispatch for a virtual implementation of opcard
pub mod dispatch {

    use trussed::{
        backend::{Backend as _, BackendId},
        platform::Platform,
        serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
        service::ServiceResources,
        types::Context,
    };
    use trussed_auth::AuthExtension;
    use trussed_auth_backend::{AuthBackend, AuthContext, FilesystemLayout, MAX_HW_KEY_LEN};
    use trussed_chunked::ChunkedExtension;
    use trussed_core::{
        api::{reply, request, Reply, Request},
        types::{Bytes, Location},
        Error,
    };
    use trussed_staging::{StagingBackend, StagingContext};
    use trussed_wrap_key_to_file::WrapKeyToFileExtension;

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
        /// chunked
        Chunked,
    }

    impl From<Extension> for u8 {
        fn from(extension: Extension) -> Self {
            match extension {
                Extension::Auth => 0,
                Extension::WrapKeyToFile => 1,
                Extension::Chunked => 2,
            }
        }
    }

    impl TryFrom<u8> for Extension {
        type Error = Error;

        fn try_from(id: u8) -> Result<Self, Self::Error> {
            match id {
                0 => Ok(Extension::Auth),
                1 => Ok(Extension::WrapKeyToFile),
                2 => Ok(Extension::Chunked),
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

    #[allow(missing_debug_implementations)]
    /// Dispatch context for the backends required by opcard
    #[derive(Default)]
    pub struct DispatchContext {
        auth: AuthContext,
        staging: StagingContext,
    }

    impl Dispatch {
        /// Create a new dispatch using the internal filesystem
        pub fn new() -> Self {
            Self {
                auth: AuthBackend::new(Location::Internal, FilesystemLayout::V0),
                staging: StagingBackend::new(),
            }
        }

        /// Create a new dispatch using the internal filesystem and a key derived from hardware parameters
        pub fn with_hw_key(hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
            Self {
                auth: AuthBackend::with_hw_key(Location::Internal, hw_key, FilesystemLayout::V0),
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
                    Extension::WrapKeyToFile | Extension::Chunked => {
                        Err(Error::RequestNotAvailable)
                    }
                },
                Backend::Staging => match extension {
                    Extension::WrapKeyToFile => <StagingBackend as ExtensionImpl<
                        WrapKeyToFileExtension,
                    >>::extension_request_serialized(
                        &mut self.staging,
                        &mut ctx.core,
                        &mut ctx.backends.staging,
                        request,
                        resources,
                    ),
                    Extension::Chunked => <StagingBackend as ExtensionImpl<
                        ChunkedExtension,
                    >>::extension_request_serialized(
                        &mut self.staging,
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
    impl ExtensionId<ChunkedExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Chunked;
    }
}

use std::path::PathBuf;
use trussed::{
    pipe::TrussedChannel,
    virt::{self, Client, Runner, StorageConfig, StoreConfig},
};
use trussed_core::types::Bytes;

/// Client type using a dispatcher with the backends required by opcard
pub type VirtClient<'a> = Client<'a, dispatch::Dispatch>;

/// Run a client using a provided store
pub fn with_client<R, F>(store: StoreConfig, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            dispatch::Dispatch::with_hw_key(Bytes::from(b"some bytes")),
            dispatch::BACKENDS,
            f,
        )
    })
}

/// Run the backend with the extensions required by opcard
/// using storage backed by a file
pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
    P: Into<PathBuf>,
{
    let store = StoreConfig {
        internal: StorageConfig::filesystem(internal.into()),
        external: StorageConfig::ram(),
        volatile: StorageConfig::ram(),
    };
    with_client(store, client_id, f)
}

/// Run the backend with the extensions required by opcard
/// using a RAM file storage
pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    with_client(StoreConfig::ram(), client_id, f)
}

/// Run a client using a provided store, leaking the interchange to achieve static lifetime of the
/// client
pub fn with_leaking_client<R, F>(store: StoreConfig, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'static>) -> R,
{
    virt::with_platform(store, |platform| {
        let channel = Box::leak(Box::new(TrussedChannel::new()));
        let mut runner = Runner::new();
        #[expect(clippy::unwrap_used)]
        let (requester, responder) = channel.split().unwrap();
        runner.add_endpoint(responder, client_id, dispatch::BACKENDS);
        let dispatch = dispatch::Dispatch::with_hw_key(Bytes::from(b"some bytes"));
        let client = Client::new(requester, runner.syscall(), None);
        runner.run(platform, dispatch, || f(client))
    })
}
