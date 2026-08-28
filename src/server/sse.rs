//! SSE event streaming: slot accounting, the lag-surviving terminal-bounded
//! stream, and the engine-event to wire-event mapping.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::Sse;
use tokio_stream::{Stream, wrappers::BroadcastStream};

use crate::api::types::ScanEvent;

use super::error::ApiError;
use super::state::AppState;

/// Cap on concurrent SSE event streams so hung tabs cannot hoard broadcast
/// receivers; the UI needs one, extras are an abuse signal.
pub(crate) const MAX_SSE_CONNECTIONS: usize = 4;

/// One concurrent SSE stream per app slot; the slot is held by the returned
/// stream for the connection's lifetime, so a dropped connection frees it.
pub(crate) async fn events(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<axum::response::sse::Event, Infallible>>>, ApiError> {
    let Some(slot) = try_acquire_sse_slot(&state.sse_connections) else {
        return Err(ApiError::too_many("too many open event streams"));
    };
    // Subscribe BEFORE reading the terminal state: a finish landing between
    // the old is_running() check and the subscribe lost the terminal for that
    // client. With the receiver already attached, a terminal emitted after it
    // arrives on the live stream, and one emitted before it is replayed from
    // last_terminal — exactly-once either way. The (epoch, terminal) state is
    // authoritative because start_scan records the terminal at emit time,
    // before the running flag clears.
    let rx = state.controller.subscribe();
    let current_epoch = state.run_epoch.load(Ordering::SeqCst);
    let replay = state
        .last_terminal
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .filter(|(epoch, _)| *epoch == current_epoch)
        .map(|(_, ev)| ev);
    let stream: Pin<Box<dyn Stream<Item = Result<axum::response::sse::Event, Infallible>> + Send>> =
        Box::pin(TerminalBounded {
            rx: BroadcastStream::new(rx),
            _slot: slot,
            done: false,
            // A terminal from an ALREADY-FINISHED run is context, not an
            // end-of-stream signal for THIS connection: closing here would
            // make every idle browser EventSource reconnect-storm (connect ->
            // replay -> close -> reconnect) and miss the next run's events.
            // Deliver it once, then keep waiting for a future run's live
            // tail — only a fresh live terminal ends the stream.
            replay: replay.map(|ev| (ev, false)),
            last_terminal: Arc::clone(&state.last_terminal),
            epoch: current_epoch,
        });
    Ok(Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default()))
}

use std::pin::Pin;

/// Live SSE items off the engine's broadcast tail, optionally preceded by one
/// replayed terminal from the previous run. Ends after a LIVE run's terminal
/// event (Finished/Failed) so an in-flight response body cannot hold hyper's
/// graceful shutdown open forever. On Lagged the stream stays alive and
/// re-emits the latest terminal snapshot (if any) instead of closing, to avoid
/// EventSource reconnect storms.
pub(crate) struct TerminalBounded {
    pub(super) rx: BroadcastStream<ScanEvent>,
    pub(super) _slot: SseSlot,
    pub(super) done: bool,
    /// `Some((event, delivered))`: the previous run's terminal until it has
    /// been yielded.
    pub(super) replay: Option<(ScanEvent, bool)>,
    pub(super) last_terminal: Arc<Mutex<Option<(u64, ScanEvent)>>>,
    pub(super) epoch: u64,
}

#[allow(clippy::ref_option)]
impl Stream for TerminalBounded {
    type Item = Result<axum::response::sse::Event, Infallible>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.done {
            return std::task::Poll::Ready(None);
        }
        // The replayed terminal goes out first, exactly once; it does not
        // end the stream (see the field docs).
        if let Some((ev, delivered)) = &mut self.replay {
            if !*delivered {
                *delivered = true;
                if let Some(event) = map_event(ev.clone()) {
                    return std::task::Poll::Ready(Some(Ok(event)));
                }
            }
        }
        loop {
            match Pin::new(&mut self.rx).poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(ev))) => {
                    let terminal = matches!(ev, ScanEvent::Finished(_) | ScanEvent::Failed(_));
                    match map_event(ev) {
                        Some(event) => {
                            self.done = terminal;
                            return std::task::Poll::Ready(Some(Ok(event)));
                        }
                        None => {
                            // Unserializable payload (never expected): drop
                            // silently; a terminal still ends the stream.
                            if terminal {
                                self.done = true;
                                return std::task::Poll::Ready(None);
                            }
                        }
                    }
                }
                // Lagged: avoid closing the stream (reconnect storm). Emit a
                // fresh terminal snapshot if one exists for this epoch, then
                // keep listening for live events.
                std::task::Poll::Ready(Some(Err(_lagged))) => {
                    if let Some(ev) = self
                        .last_terminal
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone()
                        .filter(|(epoch, _)| *epoch == self.epoch)
                        .map(|(_, ev)| ev)
                    {
                        if let Some(event) = map_event(ev) {
                            return std::task::Poll::Ready(Some(Ok(event)));
                        }
                    }
                    // No terminal to replay; stay alive and wait for next live event.
                    continue;
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

/// Maps an engine-domain event onto the SSE wire shape; None when the
/// payload cannot serialize (never expected; the live path drops silently).
pub(crate) fn map_event(ev: ScanEvent) -> Option<axum::response::sse::Event> {
    let retry = Duration::from_secs(3);
    match ev {
        ScanEvent::Progress(p) => axum::response::sse::Event::default()
            .retry(retry)
            .event("progress")
            .json_data(p)
            .ok(),
        ScanEvent::Result(v) => axum::response::sse::Event::default()
            .retry(retry)
            .event("result")
            .json_data(*v)
            .ok(),
        ScanEvent::Finished(s) => axum::response::sse::Event::default()
            .retry(retry)
            .event("finished")
            .json_data(s)
            .ok(),
        ScanEvent::Phase2Progress(p) => axum::response::sse::Event::default()
            .retry(retry)
            .event("phase2-progress")
            .json_data(p)
            .ok(),
        ScanEvent::Failed(payload) => axum::response::sse::Event::default()
            .retry(retry)
            .event("failed")
            .json_data(payload)
            .ok(),
    }
}

/// RAII SSE slot: acquire bumps the counter, drop releases it. The caller
/// moves the guard into the event stream so release happens when the
/// connection dies, not when the handler returns.
pub(crate) fn try_acquire_sse_slot(total: &Arc<AtomicUsize>) -> Option<SseSlot> {
    if total.fetch_add(1, Ordering::SeqCst) >= MAX_SSE_CONNECTIONS {
        total.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    Some(SseSlot(Arc::clone(total)))
}

pub(crate) struct SseSlot(Arc<AtomicUsize>);

impl Drop for SseSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
