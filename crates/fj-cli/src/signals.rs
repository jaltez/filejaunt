//! Signal handling: SIGINT/SIGTERM = clean cancel, SIGUSR1 = pause,
//! SIGUSR2 = resume. The pause flag stops the sender's push loop.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub fn install(pause_flag: Arc<AtomicBool>) {
    #[cfg(unix)]
    {
        let flag = pause_flag.clone();
        tokio::spawn(async move {
            if let Ok(mut sig) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
            {
                while sig.recv().await.is_some() {
                    flag.store(true, Ordering::SeqCst);
                    eprintln!("paused (SIGUSR1; SIGUSR2 to resume)");
                }
            }
        });
        let flag2 = pause_flag;
        tokio::spawn(async move {
            if let Ok(mut sig) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())
            {
                while sig.recv().await.is_some() {
                    flag2.store(false, Ordering::SeqCst);
                    eprintln!("resumed");
                }
            }
        });
    }
}
