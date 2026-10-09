//! Linking this installation to an account over its signaling connection,
//! and signing out so that the link is removed before the token ends.

use std::time::Duration;

use surf_rac_protocol::{ClientMessage, ServerMessage, WsErrorCode};
use surf_rac_session::signaling::SignalingClient;

use crate::api::Api;

/// How long the server has to answer a link or unlink.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// Why linking this installation to an account failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// The server refused the session token.
    #[error("the account session was refused")]
    Rejected,
    /// The server did not answer in time.
    #[error("the server did not answer")]
    Timeout,
    /// The signaling connection ended first.
    #[error("the connection to the server was lost")]
    Closed,
}

/// Links the installation behind `signaling` to the account that issued
/// `token` and returns the account's username.
///
/// The server answers `linked`, or a `forbidden` error for a token it does
/// not accept. Linking an installation that is already linked succeeds.
pub async fn link(signaling: &SignalingClient, token: &str) -> Result<String, LinkError> {
    let mut events = signaling.subscribe();
    signaling
        .send(ClientMessage::LinkAccount {
            token: token.to_string(),
        })
        .await
        .map_err(|_| LinkError::Closed)?;
    tokio::time::timeout(ANSWER_TIMEOUT, async {
        loop {
            match events.recv().await {
                None => return Err(LinkError::Closed),
                Some(ServerMessage::Linked { username }) => return Ok(username),
                Some(ServerMessage::Error {
                    code: WsErrorCode::Forbidden,
                    ..
                }) => return Err(LinkError::Rejected),
                Some(_) => {}
            }
        }
    })
    .await
    .unwrap_or(Err(LinkError::Timeout))
}

/// Removes the installation behind `signaling` from the account that issued
/// `token`; returns whether the server confirmed it.
///
/// Unlinking an installation that is not linked is confirmed as well.
pub async fn unlink(signaling: &SignalingClient, token: &str) -> bool {
    let mut events = signaling.subscribe();
    if signaling
        .send(ClientMessage::UnlinkAccount {
            token: token.to_string(),
        })
        .await
        .is_err()
    {
        return false;
    }
    tokio::time::timeout(ANSWER_TIMEOUT, async {
        loop {
            match events.recv().await {
                None => return false,
                Some(ServerMessage::Unlinked) => return true,
                Some(ServerMessage::Error {
                    code: WsErrorCode::Forbidden,
                    ..
                }) => return false,
                Some(_) => {}
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Signs the account of `api`'s token out: unlinks the installation behind
/// `signaling` first, when there is a connection, then ends the session on
/// the server. Returns whether the installation was unlinked.
///
/// Ending the session does not remove the link on the server, so an
/// installation signed out without a connection stays in the account's
/// device list.
pub async fn sign_out(signaling: Option<&SignalingClient>, api: &Api) -> bool {
    let Some(token) = api.token() else {
        return false;
    };
    let unlinked = match signaling {
        Some(signaling) => unlink(signaling, token).await,
        None => false,
    };
    if !unlinked {
        tracing::warn!("the installation could not be unlinked from the account");
    }
    if let Err(e) = api.logout().await {
        tracing::warn!(error = %e, "the account session could not be ended on the server");
    }
    unlinked
}
