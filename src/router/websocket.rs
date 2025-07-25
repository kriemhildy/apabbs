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
        ws::{Utf8Bytes, WebSocket},
    },
    http::{HeaderMap, Method},
    response::Response,
};
use axum_extra::extract::CookieJar;
use serde_json::json;
use tokio::sync::broadcast::Receiver;

/// Returns post message JSON
fn post_message_json(state: &AppState, post: &Post, user: &User) -> Option<serde_json::Value> {
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
    Some(json!({"type": "post", "key": post.key, "html": html}))
}

/// Return account message JSON
fn account_message_json(
    state: &AppState,
    msg_account: &Account,
    user: &User,
) -> Option<serde_json::Value> {
    let mut map = serde_json::Map::new();
    let user_account = user.account.as_ref()?;
    map.insert("type".to_string(), json!("account"));

    if msg_account.id == user_account.id {
        map.insert("reason".to_string(), json!("owner"));
        // Leaving the username unset indicates it has been rejected
        if msg_account.role != AccountRole::Rejected {
            map.insert("username".to_string(), json!(msg_account.username));
        }
        Some(map.into())
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
        map.insert("reason".to_string(), json!("admin"));
        map.insert("username".to_string(), json!(msg_account.username));
        map.insert("html".to_string(), json!(html));
        Some(map.into())
    } else {
        None
    }
}

/// Inner function to process the WebSocket connection
async fn watch_receiver(
    State(state): State<AppState>,
    mut socket: WebSocket,
    mut receiver: Receiver<AppMessage>,
    user: User,
) {
    use axum::extract::ws::Message;
    use bytes::Bytes;
    use tokio::time::{Duration, Instant, interval};
    let mut heartbeat = interval(Duration::from_secs(5)); // Heartbeat every 15s
    let mut last_pong = Instant::now();
    let timeout = Duration::from_secs(10); // 30s timeout for pong

    loop {
        tokio::select! {
            // Send heartbeat ping
            _ = heartbeat.tick() => {
                tracing::debug!("WebSocket heartbeat ping");
                if socket.send(Message::Ping(Bytes::new())).await.is_err() {
                    tracing::warn!("WebSocket heartbeat failed, closing connection");
                    let _ = socket.send(Message::Close(None)).await;
                    break; // client disconnect
                }
                // If no pong received in timeout, close connection
                if last_pong.elapsed() > timeout {
                    tracing::warn!("WebSocket heartbeat timeout, closing connection");
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
            // Send broadcast messages
            msg = receiver.recv() => {
                match msg {
                    Ok(msg) => {
                        let json = match msg {
                            AppMessage::Post(post) => post_message_json(&state, &post, &user),
                            AppMessage::Account(account) => account_message_json(&state, &account, &user),
                        };
                        if let Some(json) = json {
                            let json_utf8 = Utf8Bytes::from(json.to_string());
                            if socket.send(Message::Text(json_utf8)).await.is_err() {
                                break; // client disconnect
                            }
                        }
                    }
                    Err(_) => break, // broadcast channel closed
                }
            }
            // Receive messages from client (pong, etc)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Pong(_))) => {
                        tracing::debug!("WebSocket received pong");
                        last_pong = Instant::now(); // Reset pong timer
                    }
                    // Treat empty binary message as client heartbeat
                    Some(Ok(Message::Binary(ref bytes))) if bytes.is_empty() => {
                        tracing::debug!("WebSocket received client heartbeat (empty binary message)");
                        last_pong = Instant::now(); // Reset pong timer
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::debug!("WebSocket client closed connection");
                        break; // client closed connection
                    }
                    Some(Ok(_)) => {
                        // Ignore other messages
                    }
                    Some(Err(_)) | None => {
                        tracing::warn!("WebSocket error or client disconnected");
                        break; // error or client disconnected
                    }
                }
            }
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
