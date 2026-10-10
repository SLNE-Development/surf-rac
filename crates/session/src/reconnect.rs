//! Deadline for restoring a dropped media connection.

use std::time::Duration;

use tokio::time::Instant;

/// Tracks whether the room is reconnecting and when that attempt runs out.
pub(crate) struct ReconnectWatch {
    /// How long a reconnect may take.
    window: Duration,
    /// When the current reconnect attempt runs out, if one is in progress.
    deadline: Option<Instant>,
}

impl ReconnectWatch {
    /// Creates a watch allowing `window` per reconnect attempt.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            deadline: None,
        }
    }

    /// Records that the connection dropped; starts the window unless already running.
    pub fn reconnecting(&mut self) {
        if self.deadline.is_none() {
            self.deadline = Some(Instant::now() + self.window);
        }
    }

    /// Returns whether a reconnect attempt is in progress.
    pub fn is_reconnecting(&self) -> bool {
        self.deadline.is_some()
    }

    /// Records that the connection was restored.
    pub fn reconnected(&mut self) {
        self.deadline = None;
    }

    /// Resolves when a reconnect attempt has run out; pends while none is in progress.
    pub async fn expired(&mut self) {
        match self.deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns whether `expired()` resolves within `wait`.
    async fn expires_within(w: &mut ReconnectWatch, wait: Duration) -> bool {
        tokio::time::timeout(wait, w.expired()).await.is_ok()
    }

    /// A reconnect watch expires once the window has passed since the first
    /// reconnecting signal, and a repeated signal does not restart it.
    #[tokio::test(start_paused = true)]
    async fn expires_after_window() {
        let mut w = ReconnectWatch::new(Duration::from_secs(30));
        w.reconnecting();
        assert!(!expires_within(&mut w, Duration::from_secs(29)).await);
        w.reconnecting();
        assert!(expires_within(&mut w, Duration::from_secs(2)).await);
    }

    /// Reconnecting cancels the pending expiry, and a later reconnecting signal starts
    /// a fresh window.
    #[tokio::test(start_paused = true)]
    async fn reconnected_cancels() {
        let mut w = ReconnectWatch::new(Duration::from_secs(30));
        w.reconnecting();
        assert!(!expires_within(&mut w, Duration::from_secs(20)).await);
        w.reconnected();
        assert!(!expires_within(&mut w, Duration::from_secs(60)).await);
        w.reconnecting();
        assert!(!expires_within(&mut w, Duration::from_secs(29)).await);
        assert!(expires_within(&mut w, Duration::from_secs(2)).await);
    }

    /// A watch that never saw a reconnecting signal does not expire.
    #[tokio::test(start_paused = true)]
    async fn idle_never_expires() {
        let mut w = ReconnectWatch::new(Duration::from_secs(30));
        assert!(!expires_within(&mut w, Duration::from_secs(3600)).await);
    }
}
