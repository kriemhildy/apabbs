//! Real-time updates for posts and accounts via WebSocket.
//!
//! This module handles WebSocket connections for real-time updates on posts and account changes.
//! It sends JSON messages for post updates and account changes to connected clients.

use super::{errors::ResponseError, helpers::init_user};
use crate::{
    AppMessage, AppState,
    post::{Post, PostStatus},
    user::{Account, AccountRole, User},
    utils::render,
};
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, Utf8Bytes, WebSocket},
    },
    http::{HeaderMap, Method},
    response::Response,
};
use axum_extra::extract::CookieJar;
use tokio::sync::broadcast::Receiver;

/// Returns post message JSON
pub fn post_message_json(state: &AppState, post: &Post, user: &User) -> Option<serde_json::Value> {
    // Determine if this post should be sent to the user
    let should_send = post.author(user)
        || match user.account {
            Some(ref account) => match account.role {
                AccountRole::Admin => true,
                AccountRole::Mod => {
                    !matches!(post.status, PostStatus::Rejected | PostStatus::Reported)
                }
                _ => post.status == PostStatus::Approved,
            },
            None => post.status == PostStatus::Approved,
        };
    if !should_send {
        return None; // Skip sending this post
    }
    // Render post HTML and send as JSON
    let html = match render(state, "post.jinja", minijinja::context!(post, user)) {
        Ok(html) => html,
        Err(e) => {
            tracing::error!("Failed to render post for websocket: {:?}", e);
            return None;
        }
    };
    Some(serde_json::json!({"key": post.key, "html": html}))
}

/// Return account message JSON
pub fn account_message_json(
    state: &AppState,
    msg_account: &Account,
    user: &User,
) -> Option<serde_json::Value> {
    // Send JS for adding pending accounts, removing pending accounts, and updating account owner view
    let user_account = user.account.as_ref()?;
    if msg_account.id == user_account.id {
        Some(serde_json::json!({"username": msg_account.username}))
    } else if user_account.role == AccountRole::Admin {
        let html = match render(
            state,
            "pending_account.jinja",
            minijinja::context!(account => msg_account, user),
        ) {
            Ok(html) => html,
            Err(e) => {
                tracing::error!("Failed to render pending account for websocket: {:?}", e);
                return None;
            }
        };
        Some(serde_json::json!({"username": msg_account.username, "html": html}))
    } else {
        None // Non-admins should not receive updates about other accounts
    }
}

/// Inner function to process the WebSocket connection
pub async fn watch_receiver(
    State(state): State<AppState>,
    mut socket: WebSocket,
    mut receiver: Receiver<AppMessage>,
    user: User,
) {
    while let Ok(msg) = receiver.recv().await {
        let json = match msg {
            AppMessage::Post(post) => post_message_json(&state, &post, &user),
            AppMessage::Account(account) => account_message_json(&state, &account, &user),
        };
        if json.is_none() {
            continue; // Skip if no JSON to send
        }
        let json_utf8 = Utf8Bytes::from(json.unwrap().to_string());

        if socket.send(Message::Text(json_utf8)).await.is_err() {
            break; // client disconnect
        }
    }
}

/// Handles WebSocket upgrade requests for real-time updates
pub async fn web_socket(
    method: Method,
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ResponseError> {
    let mut tx = state.db.begin().await?;

    // Initialize user from session
    let (user, _jar) = init_user(jar, &mut tx, method, &headers, None).await?;

    // Subscribe to broadcast channel and upgrade connection
    let receiver = state.sender.subscribe();
    let state_clone = state.clone();
    Ok(
        upgrade
            .on_upgrade(move |socket| watch_receiver(State(state_clone), socket, receiver, user)),
    )
}
