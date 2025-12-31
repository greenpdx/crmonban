//! Async Analysis Queue
//!
//! Manages asynchronous LLM analysis requests with rate limiting and retries.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use super::config::{AnalysisType, QueueConfig, TriagePriority};
use super::prompts::PromptContext;

/// Analysis request in the queue
#[derive(Debug, Clone)]
pub struct AnalysisRequest {
    /// Unique request ID
    pub id: u64,
    /// Analysis type
    pub analysis_type: AnalysisType,
    /// Prompt context
    pub context: PromptContext,
    /// Priority (higher = more urgent)
    pub priority: RequestPriority,
    /// Timestamp when queued
    pub queued_at: DateTime<Utc>,
    /// Number of retries
    pub retries: usize,
    /// Callback channel for result
    pub result_tx: Option<mpsc::Sender<AnalysisResult>>,
}

/// Request priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl From<TriagePriority> for RequestPriority {
    fn from(p: TriagePriority) -> Self {
        match p {
            TriagePriority::P1 => RequestPriority::Critical,
            TriagePriority::P2 => RequestPriority::High,
            TriagePriority::P3 => RequestPriority::Normal,
            TriagePriority::P4 => RequestPriority::Low,
        }
    }
}

/// Analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Request ID
    pub request_id: u64,
    /// Analysis type
    pub analysis_type: AnalysisType,
    /// Success or error
    pub success: bool,
    /// Response text (if successful)
    pub response: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Model used
    pub model: Option<String>,
    /// Tokens used
    pub tokens_used: Option<usize>,
}

impl AnalysisResult {
    /// Create a successful result
    pub fn success(request_id: u64, analysis_type: AnalysisType, response: String, duration_ms: u64) -> Self {
        Self {
            request_id,
            analysis_type,
            success: true,
            response: Some(response),
            error: None,
            duration_ms,
            model: None,
            tokens_used: None,
        }
    }

    /// Create a failed result
    pub fn failure(request_id: u64, analysis_type: AnalysisType, error: String) -> Self {
        Self {
            request_id,
            analysis_type,
            success: false,
            response: None,
            error: Some(error),
            duration_ms: 0,
            model: None,
            tokens_used: None,
        }
    }

    /// Set model information
    pub fn with_model(mut self, model: &str, tokens: usize) -> Self {
        self.model = Some(model.to_string());
        self.tokens_used = Some(tokens);
        self
    }
}

/// Queue statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    /// Total requests queued
    pub total_queued: u64,
    /// Total requests processed
    pub total_processed: u64,
    /// Successful requests
    pub successful: u64,
    /// Failed requests
    pub failed: u64,
    /// Retried requests
    pub retries: u64,
    /// Dropped requests (queue full)
    pub dropped: u64,
    /// Current queue depth
    pub queue_depth: usize,
    /// Average processing time (ms)
    pub avg_processing_ms: u64,
}

/// Analysis queue
pub struct AnalysisQueue {
    config: QueueConfig,
    /// Priority queues (index = priority level)
    queues: Arc<RwLock<[VecDeque<AnalysisRequest>; 4]>>,
    /// Statistics
    stats: Arc<RwLock<QueueStats>>,
    /// Next request ID
    next_id: Arc<Mutex<u64>>,
    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

impl AnalysisQueue {
    /// Create a new analysis queue
    pub fn new(config: QueueConfig) -> Self {
        Self {
            config,
            queues: Arc::new(RwLock::new([
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ])),
            stats: Arc::new(RwLock::new(QueueStats::default())),
            next_id: Arc::new(Mutex::new(1)),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Enqueue an analysis request
    pub async fn enqueue(
        &self,
        analysis_type: AnalysisType,
        context: PromptContext,
        priority: RequestPriority,
    ) -> Result<u64, String> {
        // Check queue capacity
        let current_depth = self.queue_depth().await;
        if current_depth >= self.config.max_size {
            let mut stats = self.stats.write().await;
            stats.dropped += 1;
            return Err("Queue full".to_string());
        }

        // Generate request ID
        let id = {
            let mut next = self.next_id.lock().await;
            let id = *next;
            *next += 1;
            id
        };

        let request = AnalysisRequest {
            id,
            analysis_type,
            context,
            priority,
            queued_at: Utc::now(),
            retries: 0,
            result_tx: None,
        };

        // Add to appropriate priority queue
        {
            let mut queues = self.queues.write().await;
            queues[priority as usize].push_back(request);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_queued += 1;
            stats.queue_depth = current_depth + 1;
        }

        debug!("Enqueued analysis request {} (priority {:?})", id, priority);
        Ok(id)
    }

    /// Enqueue with result callback
    pub async fn enqueue_with_callback(
        &self,
        analysis_type: AnalysisType,
        context: PromptContext,
        priority: RequestPriority,
        result_tx: mpsc::Sender<AnalysisResult>,
    ) -> Result<u64, String> {
        let current_depth = self.queue_depth().await;
        if current_depth >= self.config.max_size {
            return Err("Queue full".to_string());
        }

        let id = {
            let mut next = self.next_id.lock().await;
            let id = *next;
            *next += 1;
            id
        };

        let request = AnalysisRequest {
            id,
            analysis_type,
            context,
            priority,
            queued_at: Utc::now(),
            retries: 0,
            result_tx: Some(result_tx),
        };

        {
            let mut queues = self.queues.write().await;
            queues[priority as usize].push_back(request);
        }

        {
            let mut stats = self.stats.write().await;
            stats.total_queued += 1;
            stats.queue_depth = current_depth + 1;
        }

        Ok(id)
    }

    /// Dequeue next request (highest priority first)
    pub async fn dequeue(&self) -> Option<AnalysisRequest> {
        let mut queues = self.queues.write().await;

        // Check from highest to lowest priority
        for priority in (0..4).rev() {
            if let Some(request) = queues[priority].pop_front() {
                drop(queues);

                {
                    let mut stats = self.stats.write().await;
                    stats.queue_depth = stats.queue_depth.saturating_sub(1);
                }

                return Some(request);
            }
        }

        None
    }

    /// Requeue a request for retry
    pub async fn requeue(&self, mut request: AnalysisRequest) -> bool {
        if request.retries >= self.config.max_retries {
            warn!("Request {} exceeded max retries", request.id);
            return false;
        }

        request.retries += 1;

        {
            let mut stats = self.stats.write().await;
            stats.retries += 1;
        }

        let priority = request.priority as usize;
        {
            let mut queues = self.queues.write().await;
            queues[priority].push_back(request);
        }

        {
            let mut stats = self.stats.write().await;
            stats.queue_depth += 1;
        }

        true
    }

    /// Mark request as processed
    pub async fn mark_processed(&self, success: bool, duration_ms: u64) {
        let mut stats = self.stats.write().await;
        stats.total_processed += 1;

        if success {
            stats.successful += 1;
        } else {
            stats.failed += 1;
        }

        // Update average processing time
        let total = stats.total_processed;
        stats.avg_processing_ms = (stats.avg_processing_ms * (total - 1) + duration_ms) / total;
    }

    /// Get current queue depth
    pub async fn queue_depth(&self) -> usize {
        let queues = self.queues.read().await;
        queues.iter().map(|q| q.len()).sum()
    }

    /// Get statistics
    pub async fn stats(&self) -> QueueStats {
        let stats = self.stats.read().await;
        let mut result = stats.clone();
        result.queue_depth = self.queue_depth().await;
        result
    }

    /// Check if queue is empty
    pub async fn is_empty(&self) -> bool {
        self.queue_depth().await == 0
    }

    /// Signal shutdown
    pub async fn shutdown(&self) {
        let mut shutdown = self.shutdown.write().await;
        *shutdown = true;
    }

    /// Check if shutdown was signaled
    pub async fn is_shutdown(&self) -> bool {
        *self.shutdown.read().await
    }

    /// Get backoff delay for retry
    pub fn backoff_delay(&self, retries: usize) -> Duration {
        let base_ms = self.config.backoff_base_ms;
        let delay_ms = base_ms * (1 << retries.min(5)); // Exponential with cap
        Duration::from_millis(delay_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_queue_creation() {
        let config = QueueConfig::default();
        let queue = AnalysisQueue::new(config);

        assert!(queue.is_empty().await);
        assert_eq!(queue.queue_depth().await, 0);
    }

    #[tokio::test]
    async fn test_enqueue_dequeue() {
        let config = QueueConfig::default();
        let queue = AnalysisQueue::new(config);

        let context = PromptContext::new("Test", "High", "Test alert");
        let id = queue.enqueue(AnalysisType::Triage, context, RequestPriority::Normal)
            .await
            .unwrap();

        assert_eq!(id, 1);
        assert_eq!(queue.queue_depth().await, 1);

        let request = queue.dequeue().await.unwrap();
        assert_eq!(request.id, 1);
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let config = QueueConfig::default();
        let queue = AnalysisQueue::new(config);

        // Enqueue in low-to-high priority order
        let ctx = PromptContext::new("Test", "Low", "Test");
        queue.enqueue(AnalysisType::Triage, ctx.clone(), RequestPriority::Low).await.unwrap();
        queue.enqueue(AnalysisType::Triage, ctx.clone(), RequestPriority::High).await.unwrap();
        queue.enqueue(AnalysisType::Triage, ctx, RequestPriority::Normal).await.unwrap();

        // Should dequeue in high-to-low priority order
        let r1 = queue.dequeue().await.unwrap();
        assert_eq!(r1.priority, RequestPriority::High);

        let r2 = queue.dequeue().await.unwrap();
        assert_eq!(r2.priority, RequestPriority::Normal);

        let r3 = queue.dequeue().await.unwrap();
        assert_eq!(r3.priority, RequestPriority::Low);
    }

    #[tokio::test]
    async fn test_backoff_delay() {
        let config = QueueConfig::default();
        let queue = AnalysisQueue::new(config);

        let d0 = queue.backoff_delay(0);
        let d1 = queue.backoff_delay(1);
        let d2 = queue.backoff_delay(2);

        assert!(d1 > d0);
        assert!(d2 > d1);
    }

    #[test]
    fn test_analysis_result() {
        let success = AnalysisResult::success(1, AnalysisType::Triage, "response".to_string(), 100);
        assert!(success.success);
        assert!(success.response.is_some());

        let failure = AnalysisResult::failure(2, AnalysisType::Explain, "error".to_string());
        assert!(!failure.success);
        assert!(failure.error.is_some());
    }
}
