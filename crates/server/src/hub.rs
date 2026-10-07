//! Registry of online devices and their WebSocket connections.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use surf_rac_protocol::{DeviceId, ServerMessage};
use tokio::sync::mpsc;

/// An instruction for a connection's writer task.
#[derive(Debug, Clone, PartialEq)]
pub enum Outbound {
    /// Send this message to the client.
    Message(ServerMessage),
    /// Close the socket.
    Close,
}

/// A live connection of one device.
struct Conn {
    /// Unique ID of this connection, to tell it apart from a replacement.
    conn_id: u64,
    /// Channel to the connection's writer task.
    tx: mpsc::UnboundedSender<Outbound>,
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
    /// Returns the connection ID and the receiver its writer task drains. A
    /// previous connection of the device is told it was replaced and closed.
    /// The second value is true when the device was offline before.
    pub fn register(&self, device: DeviceId) -> (u64, mpsc::UnboundedReceiver<Outbound>, bool) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        let previous = self.lock().insert(device, Conn { conn_id, tx });
        let was_offline = previous.is_none();
        if let Some(old) = previous {
            let _ = old.tx.send(Outbound::Message(ServerMessage::Replaced));
            let _ = old.tx.send(Outbound::Close);
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

    /// Queues `msg` for `device`; returns false when the device is offline.
    pub fn send(&self, device: DeviceId, msg: ServerMessage) -> bool {
        match self.lock().get(&device) {
            Some(c) => c.tx.send(Outbound::Message(msg)).is_ok(),
            None => false,
        }
    }

    /// Closes `device`'s live connection, telling it that it was replaced.
    ///
    /// Returns true when a connection was closed.
    pub fn disconnect(&self, device: DeviceId) -> bool {
        let removed = self.lock().remove(&device);
        match removed {
            Some(c) => {
                let _ = c.tx.send(Outbound::Message(ServerMessage::Replaced));
                let _ = c.tx.send(Outbound::Close);
                true
            }
            None => false,
        }
    }
}
