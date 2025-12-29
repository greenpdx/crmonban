use crate::types::DetectionEvent;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::broadcast;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type DetectionCallback = Arc<dyn Fn(DetectionEvent) -> BoxFuture<'static, ()> + Send + Sync>;

pub struct OutputHandler {
    callbacks: Vec<DetectionCallback>,
    broadcast_tx: broadcast::Sender<DetectionEvent>,
}

impl OutputHandler {
    pub fn new(channel_capacity: usize) -> Self {
        let (broadcast_tx, _) = broadcast::channel(channel_capacity);
        Self {
            callbacks: Vec::new(),
            broadcast_tx,
        }
    }

    pub fn add_callback<F, Fut>(&mut self, callback: F)
    where
        F: Fn(DetectionEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let wrapped = Arc::new(move |event: DetectionEvent| {
            Box::pin(callback(event)) as BoxFuture<'static, ()>
        });
        self.callbacks.push(wrapped);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DetectionEvent> {
        self.broadcast_tx.subscribe()
    }

    pub async fn emit(&self, event: DetectionEvent) {
        // Send to broadcast channel (ignore if no receivers)
        let _ = self.broadcast_tx.send(event.clone());

        // Call all callbacks
        for callback in &self.callbacks {
            callback(event.clone()).await;
        }
    }

    pub fn receiver_count(&self) -> usize {
        self.broadcast_tx.receiver_count()
    }
}

impl Default for OutputHandler {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DetectionType, Severity};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_event() -> DetectionEvent {
        DetectionEvent::new(
            DetectionType::PortScan,
            Severity::Medium,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "SYN scan detected".to_string(),
        )
        .with_detector("layer2detect")
        .with_confidence(0.95)
    }

    #[tokio::test]
    async fn test_callback() {
        let mut handler = OutputHandler::new(10);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        handler.add_callback(move |_event| {
            let c = counter_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
            }
        });

        handler.emit(make_event()).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        handler.emit(make_event()).await;
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_broadcast() {
        let handler = OutputHandler::new(10);
        let mut rx = handler.subscribe();

        handler.emit(make_event()).await;

        let received = rx.recv().await.unwrap();
        assert_eq!(received.confidence, 0.95);
    }
}
