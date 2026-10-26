//! Cancellation shared by the async caller, transport and blocking guest.
use crate::error::ClientError;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone)]
pub(crate) struct Cancellation(Arc<Inner>);
struct Inner {
    cancelled: AtomicBool,
    signal: tokio::sync::watch::Sender<bool>,
}
impl Cancellation {
    pub fn new() -> Self {
        let (signal, _) = tokio::sync::watch::channel(false);
        Self(Arc::new(Inner {
            cancelled: AtomicBool::new(false),
            signal,
        }))
    }
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.signal.send_replace(true);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }
    pub fn check(&self) -> Result<(), ClientError> {
        if self.is_cancelled() {
            Err(ClientError::Sap("Store request cancelled".into()))
        } else {
            Ok(())
        }
    }
    pub async fn cancelled(&self) {
        let mut receiver = self.0.signal.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
    pub fn guard(&self) -> CancelOnDrop {
        CancelOnDrop(self.clone())
    }
}
pub(crate) struct CancelOnDrop(Cancellation);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn dropping_caller_wakes_current_and_later_waiters() {
        let token = Cancellation::new();
        let worker = token.clone();
        let wait = tokio::spawn(async move {
            worker.cancelled().await;
            worker.check().is_err()
        });
        drop(token.guard());
        assert!(wait.await.unwrap());
        token.cancelled().await;
        assert!(token.is_cancelled());
    }
}
