use std::sync::Arc;
use std::convert::Infallible;
use axum::{
    extract::{State, Path, Query},
    response::sse::{Event, Sse},
    Json,
};
use futures_util::stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use crate::{models::PaginationQuery, state::AppState};

pub async fn list_events(
    State(_state): State<Arc<AppState>>,
    Query(_params): Query<PaginationQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "events": [],
        "total": 0,
        "page": 1
    }))
}

pub async fn get_event(
    State(_state): State<Arc<AppState>>,
    Path(_id): Path<String>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({}))
}

pub async fn event_stream(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.subscribe();
    let stream = BroadcastStream::new(rx)
        .filter_map(|msg| {
            msg.ok().map(|e| {
                Ok(Event::default()
                    .event("event")
                    .data(serde_json::to_string(&e).unwrap_or_default()))
            })
        });
    Sse::new(stream)
}
