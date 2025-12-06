use std::sync::Arc;
use axum::{
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::Response,
};
use crate::state::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.subscribe();

    loop {
        tokio::select! {
            // Forward events from broadcast to client
            event = rx.recv() => {
                match event {
                    Ok(e) => {
                        if let Ok(json) = serde_json::to_string(&e) {
                            if socket.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            // Handle incoming messages
            msg = socket.recv() => {
                match msg {
                    Some(Ok(_)) => {
                        // Handle client messages (subscriptions, etc)
                    }
                    _ => break,
                }
            }
        }
    }
}
