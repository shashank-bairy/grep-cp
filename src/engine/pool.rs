//! Global search worker pool, shared by all requests.
//!
//! A fixed number of threads (sized to the CPU quota) serves per-request task queues round-robin,
//! so concurrent requests share the CPU fairly instead of each spawning its own threads and
//! oversubscribing the quota. A request submits file-search tasks and receives results on a
//! channel; it controls its own look-ahead (how many tasks it has in flight).

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex};

type Task = Box<dyn FnOnce() + Send + 'static>;

struct Queue {
    tasks: Mutex<VecDeque<Task>>,
}

#[derive(Default)]
struct State {
    /// Request queues with pending tasks, served round-robin.
    ready: VecDeque<Arc<Queue>>,
}

struct Inner {
    state: Mutex<State>,
    cv: Condvar,
}

pub struct WorkerPool {
    inner: Arc<Inner>,
    threads: usize,
}

impl WorkerPool {
    pub fn new(threads: usize) -> Self {
        let threads = threads.max(1);
        let inner = Arc::new(Inner {
            state: Mutex::new(State::default()),
            cv: Condvar::new(),
        });
        for i in 0..threads {
            let inner = inner.clone();
            std::thread::Builder::new()
                .name(format!("grep-cp-search-{i}"))
                .spawn(move || worker(inner))
                .expect("spawning search worker");
        }
        Self { inner, threads }
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    /// Creates a submission handle for one request.
    pub fn session(&self) -> Session {
        Session {
            inner: self.inner.clone(),
            queue: Arc::new(Queue {
                tasks: Mutex::new(VecDeque::new()),
            }),
        }
    }
}

/// One request's view of the pool. Dropping it discards tasks not yet started.
pub struct Session {
    inner: Arc<Inner>,
    queue: Arc<Queue>,
}

impl Session {
    pub fn submit(&self, f: impl FnOnce() + Send + 'static) {
        let was_empty = {
            let mut t = self.queue.tasks.lock().unwrap();
            let was_empty = t.is_empty();
            t.push_back(Box::new(f));
            was_empty
        };
        if was_empty {
            let mut st = self.inner.state.lock().unwrap();
            if !st.ready.iter().any(|q| Arc::ptr_eq(q, &self.queue)) {
                st.ready.push_back(self.queue.clone());
            }
            drop(st);
            self.inner.cv.notify_one();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.queue.tasks.lock().unwrap().clear();
        self.inner
            .state
            .lock()
            .unwrap()
            .ready
            .retain(|q| !Arc::ptr_eq(q, &self.queue));
    }
}

fn worker(inner: Arc<Inner>) {
    loop {
        let task = {
            let mut st = inner.state.lock().unwrap();
            loop {
                if let Some(q) = st.ready.pop_front() {
                    let mut tasks = q.tasks.lock().unwrap();
                    if let Some(t) = tasks.pop_front() {
                        let more = !tasks.is_empty();
                        drop(tasks);
                        if more {
                            // Round-robin: the request goes to the back of the line.
                            st.ready.push_back(q);
                        }
                        break t;
                    }
                    continue;
                }
                st = inner.cv.wait(st).unwrap();
            }
        };
        // A panicking task must not take the worker down; the submitter sees its result channel
        // close and reports the file as failed.
        let _ = catch_unwind(AssertUnwindSafe(task));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn runs_all_tasks_and_survives_panics() {
        let pool = WorkerPool::new(2);
        let s = pool.session();
        let n = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = std::sync::mpsc::channel();
        for i in 0..50 {
            let n = n.clone();
            let tx = tx.clone();
            s.submit(move || {
                if i == 7 {
                    panic!("boom");
                }
                n.fetch_add(1, Ordering::SeqCst);
                tx.send(i).unwrap();
            });
        }
        drop(tx);
        let got: Vec<i32> = rx.iter().collect();
        assert_eq!(got.len(), 49);
        assert_eq!(n.load(Ordering::SeqCst), 49);
    }

    #[test]
    fn requests_are_served_round_robin() {
        // One worker, two requests: the second must not wait for all of the first's tasks.
        let pool = WorkerPool::new(1);
        let a = pool.session();
        let b = pool.session();
        let order = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        // Block the worker so both queues fill before anything runs.
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        {
            let gate = gate.clone();
            a.submit(move || {
                let (m, c) = &*gate;
                let mut open = m.lock().unwrap();
                while !*open {
                    open = c.wait(open).unwrap();
                }
            });
        }
        std::thread::sleep(Duration::from_millis(20));
        for (name, s) in [("a", &a), ("b", &b)] {
            for i in 0..3 {
                let order = order.clone();
                let tx = tx.clone();
                s.submit(move || {
                    order.lock().unwrap().push(format!("{name}{i}"));
                    tx.send(()).unwrap();
                });
            }
        }
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        for _ in 0..6 {
            rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        let o = order.lock().unwrap().clone();
        assert_eq!(o, ["a0", "b0", "a1", "b1", "a2", "b2"], "{o:?}");
    }
}
