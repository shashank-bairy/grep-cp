//! Shared application state: settings, catalog, and the global concurrency limiter.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::Settings;
use crate::engine::WorkerPool;
use crate::errors::{ToolError, ToolResult};
use crate::logs::catalog::Catalog;

pub struct App {
    pub settings: Arc<Settings>,
    pub catalog: Catalog,
    /// Shared search threads (all requests).
    pub pool: WorkerPool,
    slots: Arc<Semaphore>,
}

impl App {
    pub fn new(settings: Arc<Settings>) -> anyhow::Result<Arc<Self>> {
        let catalog = Catalog::new(settings.clone())?;
        let slots = Arc::new(Semaphore::new(settings.limits().max_concurrent_requests));
        let pool = WorkerPool::new(settings.limits().search_threads);
        Ok(Arc::new(Self {
            settings,
            catalog,
            pool,
            slots,
        }))
    }

    /// Waits (bounded) for a global search slot. Searches hold one slot for their whole run.
    pub async fn acquire(&self) -> ToolResult<OwnedSemaphorePermit> {
        let wait = Duration::from_secs(self.settings.limits().queue_wait_secs);
        match tokio::time::timeout(wait, self.slots.clone().acquire_owned()).await {
            Ok(Ok(p)) => Ok(p),
            Ok(Err(_)) => Err(ToolError::Internal("limiter closed".into())),
            Err(_) => Err(ToolError::Busy(
                self.settings.limits().max_concurrent_requests,
            )),
        }
    }
}
