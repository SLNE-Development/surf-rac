//! Linking this installation to an account over its signaling connection,
//! and signing out so that the link is removed before the session ends.

use std::time::Duration;

use surf_rac_protocol::{ClientMessage, DeviceId, ServerMessage};
use surf_rac_session::signaling::{SignalingClient, SignalingEvents};

use crate::api::{Api, ApiError};

/// How long the server has to answer a link.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// Why linking this installation to an account did not succeed.
///
/// The server's refusal of a token cannot be told apart from its other
/// errors on the connection, so a refused token shows up as a timeout.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// The server did not confirm the link in time.
    #[error("the server did not confirm the link")]
    Timeout,
    /// The signaling connection ended first.
    #[error("the connection to the server was lost")]
    Closed,
}

/// Messages arriving on a signaling connection.
pub(crate) enum Replies {
    /// The messages of a live connection.
    Events(SignalingEvents),
    /// Messages fed by a test.
    #[cfg(test)]
    Channel(tokio::sync::mpsc::UnboundedReceiver<ServerMessage>),
}

impl Replies {
    /// Returns the next message, or `None` once the connection ended.
    async fn recv(&mut self) -> Option<ServerMessage> {
        match self {
            Replies::Events(events) => events.recv().await,
            #[cfg(test)]
            Replies::Channel(rx) => rx.recv().await,
        }
    }
}

/// Waits up to `wait` for a `linked` message on `replies` and returns its username.
///
/// Every other message, error frames included, is skipped: they may answer
/// other requests on the same connection.
pub(crate) async fn await_linked(
    replies: &mut Replies,
    wait: Duration,
) -> Result<String, LinkError> {
    tokio::time::timeout(wait, async {
        loop {
            match replies.recv().await {
                None => return Err(LinkError::Closed),
                Some(ServerMessage::Linked { username }) => return Ok(username),
                Some(_) => {}
            }
        }
    })
    .await
    .unwrap_or(Err(LinkError::Timeout))
}

/// Links the installation behind `signaling` to the account that issued
/// `token` and returns the account's username.
///
/// Succeeds only on the server's `linked` confirmation. Linking an
/// installation that is already linked succeeds.
pub async fn link(signaling: &SignalingClient, token: &str) -> Result<String, LinkError> {
    let mut replies = Replies::Events(signaling.subscribe());
    signaling
        .send(ClientMessage::LinkAccount {
            token: token.to_string(),
        })
        .await
        .map_err(|_| LinkError::Closed)?;
    await_linked(&mut replies, ANSWER_TIMEOUT).await
}

/// Signs the account of `api`'s token out: unlinks installation `device`
/// from the account over HTTP, then ends the session on the server.
///
/// Needs no signaling connection. Returns whether the installation is no
/// longer linked: it was unlinked, was not linked, or there is no
/// installation. The session is ended in every case.
pub async fn sign_out(api: &Api, device: Option<DeviceId>) -> bool {
    let unlinked = match device {
        None => true,
        Some(id) => match api.unlink_device(id).await {
            Ok(()) | Err(ApiError::NotFound) => true,
            Err(e) => {
                tracing::warn!(error = %e, "the installation could not be unlinked from the account");
                false
            }
        },
    };
    if let Err(e) = api.logout().await {
        tracing::warn!(error = %e, "the account session could not be ended on the server");
    }
    unlinked
}

#[cfg(test)]
mod tests {
    use surf_rac_protocol::WsErrorCode;
    use tokio::sync::mpsc;

    use super::*;

    /// Returns a message source that yields `messages` and then stays open.
    fn source(messages: Vec<ServerMessage>) -> (mpsc::UnboundedSender<ServerMessage>, Replies) {
        let (tx, rx) = mpsc::unbounded_channel();
        for m in messages {
            tx.send(m).unwrap();
        }
        (tx, Replies::Channel(rx))
    }

    /// Returns a `forbidden` error frame as the server sends for unrelated failures.
    fn forbidden() -> ServerMessage {
        ServerMessage::Error {
            code: WsErrorCode::Forbidden,
            message: "database error".into(),
            session_id: None,
        }
    }

    #[tokio::test]
    async fn stray_forbidden_does_not_answer_a_link() {
        let (_tx, mut replies) = source(vec![
            forbidden(),
            ServerMessage::Pong,
            ServerMessage::Linked {
                username: "alice".into(),
            },
        ]);
        assert_eq!(
            await_linked(&mut replies, Duration::from_secs(1)).await,
            Ok("alice".into())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn link_without_linked_reply_times_out_even_after_forbidden() {
        let (_tx, mut replies) = source(vec![forbidden()]);
        assert_eq!(
            await_linked(&mut replies, Duration::from_secs(5)).await,
            Err(LinkError::Timeout)
        );
    }

    #[tokio::test]
    async fn link_fails_closed_when_the_connection_ends() {
        let (tx, mut replies) = source(vec![forbidden()]);
        drop(tx);
        assert_eq!(
            await_linked(&mut replies, Duration::from_secs(5)).await,
            Err(LinkError::Closed)
        );
    }
}
