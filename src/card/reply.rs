use iso7816::Status;

use core::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct Reply<'v, const R: usize>(pub &'v mut heapless::Vec<u8, R>);

impl<'v, const R: usize> Deref for Reply<'v, R> {
    type Target = &'v mut heapless::Vec<u8, R>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'v, const R: usize> DerefMut for Reply<'v, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'v, const R: usize> Reply<'v, R> {
    /// Extend the reply and return an error otherwise
    /// The MoreAvailable and GET RESPONSE mechanisms are handled by adpu_dispatch
    ///
    /// Named expand and not extend to avoid conflicts with Deref
    pub fn expand(&mut self, data: &[u8]) -> Result<(), Status> {
        self.0.extend_from_slice(data).map_err(|_| {
            log::error!("Buffer full");
            Status::NotEnoughMemory
        })
    }
}
