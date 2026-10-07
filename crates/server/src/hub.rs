//! Registry of online devices and their WebSocket connections.
//!
//! Each connection has a bounded outbound queue. Closing a connection drops
//! its queue's sender, so the writer task ends after draining what is queued,
//! even when the queue is full.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use surf_rac_protocol::{DeviceId, ServerMessage};
use tokio::sync::mpsc;

/// Messages a connection's outbound queue holds before sends to it fail.
pub const OUTBOUND_CAPACITY: usize = 256;

/// A live connection of one device.
struct Conn {
    /// Unique ID of this connection, to tell it apart from a replacement.
    conn_id: u64,
    /// Queue to the connection's writer task.
    tx: mpsc::Sender<ServerMessage>,
}

impl Conn {
    /// Tells the connection it was replaced, if its queue has room, and drops the sender.
    fn close_replaced(self) {
        let _ = self.tx.try_send(ServerMessage::Replaced);
    }
}

/// Maps each online device to its single live connection; cheap to clone.
#[derive(Clone, Default)]
pub struct Hub {
    /// Live connections by device.
    conns: Arc<Mutex<HashMap<DeviceId, Conn>>>,
    /// Source of connection IDs.
    next_conn_id: Arc<AtomicU64>,
}

impl Hub {
    /// Locks the connection map, recovering from a poisoned lock.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<DeviceId, Conn>> {
        self.conns.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns whether `device` currently has a live connection.
    pub fn is_online(&self, device: DeviceId) -> bool {
        self.lock().contains_key(&device)
    }

    /// Makes a new connection the live one for `device`.
    ///
    /// Returns the connection ID, the receiver its writer task drains, and
    /// whether the device was offline before. A previous connection of the
    /// device is told it was replaced and its queue is closed.
    pub fn register(&self, device: DeviceId) -> (u64, mpsc::Receiver<ServerMessage>, bool) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let previous = self.lock().insert(device, Conn { conn_id, tx });
        let was_offline = previous.is_none();
        if let Some(old) = previous {
            old.close_replaced();
        }
        (conn_id, rx, was_offline)
    }

    /// Removes `device`'s entry if it still belongs to connection `conn_id`.
    ///
    /// Returns true when the entry was removed, i.e. the device is now offline.
    pub fn unregister(&self, device: DeviceId, conn_id: u64) -> bool {
        let mut conns = self.lock();
        match conns.get(&device) {
            Some(c) if c.conn_id == conn_id => {
                conns.remove(&device);
                true
            }
            _ => false,
        }
    }

    /// Queues `msg` for `device`; returns false when the device is offline or its queue is full.
    pub fn send(&self, device: DeviceId, msg: ServerMessage) -> bool {
        match self.lock().get(&device) {
            Some(c) => c.tx.try_send(msg).is_ok(),
            None => false,
        }
    }

    /// Closes `device`'s live connection, telling it that it was replaced.
    ///
    /// Returns true when a connection was closed, i.e. the device is now offline.
    pub fn disconnect(&self, device: DeviceId) -> bool {
        let removed = self.lock().remove(&device);
        match removed {
            Some(c) => {
                c.close_replaced();
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u32) -> DeviceId {
        DeviceId::new(n).unwrap()
    }

    #[test]
    fn send_to_full_queue_fails() {
        let hub = Hub::default();
        let (_conn, _rx, _) = hub.register(id(100_000_001));
        for _ in 0..OUTBOUND_CAPACITY {
            assert!(hub.send(id(100_000_001), ServerMessage::Pong));
        }
        assert!(!hub.send(id(100_000_001), ServerMessage::Pong));
    }

    #[tokio::test]
    async fn disconnect_closes_even_when_queue_full() {
        let hub = Hub::default();
        let (_conn, mut rx, _) = hub.register(id(100_000_001));
        while hub.send(id(100_000_001), ServerMessage::Pong) {}
        assert!(hub.disconnect(id(100_000_001)));
        let mut drained = 0;
        while let Some(out) = rx.recv().await {
            drained += 1;
            assert!(drained <= OUTBOUND_CAPACITY + 2, "receiver never ended");
            let _ = out;
        }
        assert!(!hub.is_online(id(100_000_001)));
    }
}
