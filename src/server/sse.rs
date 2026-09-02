use std::collections::{HashSet, VecDeque};
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::response::Sse;
use tokio_stream::{Stream, wrappers::BroadcastStream};

use crate::api::types::ScanEvent;

use super::error::ApiError;
use super::state::AppState;

pub(crate) const MAX_SSE_CONNECTIONS: usize = 4;

const RESYNC_MIN_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) async fn events(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<axum::response::sse::Event, Infallible>>>, ApiError> {
    let Some(slot) = try_acquire_sse_slot(&state.sse_connections) else {
        return Err(ApiError::too_many("too many open event streams"));
    };
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
            replay: replay.map(|ev| (ev, false)),
            last_terminal: Arc::clone(&state.last_terminal),
            epoch: current_epoch,
            controller: Arc::clone(&state.controller),
            seen: HashSet::new(),
            pending: VecDeque::new(),
            last_resync: None,
        });
    Ok(Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default()))
}

use std::pin::Pin;

pub(crate) struct TerminalBounded {
    pub(super) rx: BroadcastStream<ScanEvent>,
    pub(super) _slot: SseSlot,
    pub(super) done: bool,
    pub(super) replay: Option<(ScanEvent, bool)>,
    pub(super) last_terminal: Arc<Mutex<Option<(u64, ScanEvent)>>>,
    pub(super) epoch: u64,
    pub(super) controller: Arc<crate::engine::ScanController>,
    pub(super) seen: HashSet<(IpAddr, u16)>,
    pub(super) pending: VecDeque<ScanEvent>,
    pub(super) last_resync: Option<Instant>,
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
        if let Some((ev, delivered)) = &mut self.replay
            && !*delivered
        {
            *delivered = true;
            if let Some(event) = map_event(ev.clone()) {
                return std::task::Poll::Ready(Some(Ok(event)));
            }
        }
        loop {
            if let Some(ev) = self.pending.pop_front() {
                if let Some(event) = map_event(ev) {
                    return std::task::Poll::Ready(Some(Ok(event)));
                }
                continue;
            }
            match Pin::new(&mut self.rx).poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(ev))) => {
                    if let ScanEvent::Result(v) = &ev {
                        self.seen.insert((v.ip, v.port));
                    }
                    let terminal = matches!(ev, ScanEvent::Finished(_) | ScanEvent::Failed(_));
                    if terminal && matches!(&self.replay, Some((replayed, true)) if *replayed == ev)
                    {
                        self.done = true;
                        return std::task::Poll::Ready(None);
                    }
                    match map_event(ev) {
                        Some(event) => {
                            self.done = terminal;
                            return std::task::Poll::Ready(Some(Ok(event)));
                        }
                        None => {
                            if terminal {
                                self.done = true;
                                return std::task::Poll::Ready(None);
                            }
                        }
                    }
                }
                std::task::Poll::Ready(Some(Err(_lagged))) => {
                    if self
                        .last_resync
                        .is_none_or(|t| t.elapsed() >= RESYNC_MIN_INTERVAL)
                    {
                        self.last_resync = Some(Instant::now());
                        let mut to_add = Vec::new();
                        self.controller.for_each_result(|v| {
                            to_add.push(v.clone());
                        });
                        for v in to_add {
                            if self.seen.insert((v.ip, v.port)) {
                                self.pending.push_back(ScanEvent::Result(Box::new(v)));
                            }
                        }
                    }
                    if let Some(ev) = self.pending.pop_front()
                        && let Some(event) = map_event(ev)
                    {
                        return std::task::Poll::Ready(Some(Ok(event)));
                    }
                    if let Some(ev) = self
                        .last_terminal
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone()
                        .filter(|(epoch, _)| *epoch == self.epoch)
                        .map(|(_, ev)| ev)
                        && let Some(event) = map_event(ev)
                    {
                        return std::task::Poll::Ready(Some(Ok(event)));
                    }
                    continue;
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

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
