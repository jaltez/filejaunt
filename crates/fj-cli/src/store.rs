//! State persistence: session snapshots + receipts under
//! `~/.local/share/filejaunt/{sessions,receipts}` (fsync on every write).

use std::io::Write;
use std::path::{Path, PathBuf};

use fj_protocol::receipt::Receipt;

pub struct Store {
    base: PathBuf,
}

impl Store {
    pub fn new() -> std::io::Result<Store> {
        let base = directories::ProjectDirs::from("", "", "filejaunt")
            .map(|d| d.data_local_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".filejaunt"));
        let s = Store { base };
        std::fs::create_dir_all(s.sessions_dir())?;
        std::fs::create_dir_all(s.receipts_dir())?;
        Ok(s)
    }

    pub fn sessions_dir(&self) -> PathBuf {
        self.base.join("sessions")
    }

    pub fn receipts_dir(&self) -> PathBuf {
        self.base.join("receipts")
    }

    fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Save a session snapshot (`sessions/<sid>.<role>.json`); the sender
    /// and receiver of one sid keep separate files.
    pub fn save_session(&self, sid: &str, role: &str, snapshot: &str) -> std::io::Result<()> {
        let sid: String = sid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let role = if role == "send" { "send" } else { "recv" };
        Self::write_atomic(
            &self.sessions_dir().join(format!("{sid}.{role}.json")),
            snapshot.as_bytes(),
        )
    }

    pub fn load_session(&self, sid: &str, role: &str) -> Option<String> {
        let sid: String = sid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let role = if role == "send" { "send" } else { "recv" };
        std::fs::read_to_string(self.sessions_dir().join(format!("{sid}.{role}.json"))).ok()
    }

    pub fn delete_session(&self, sid: &str) {
        let sid: String = sid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let _ = std::fs::remove_file(self.sessions_dir().join(format!("{sid}.send.json")));
        let _ = std::fs::remove_file(self.sessions_dir().join(format!("{sid}.recv.json")));
        let _ = std::fs::remove_file(self.sessions_dir().join(format!("{sid}.json")));
    }

    /// Save a receipt (`receipts/<sid>-<file>.json`) and return its path.
    pub fn save_receipt(&self, receipt: &Receipt) -> std::io::Result<PathBuf> {
        let safe_name = receipt
            .sid
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>();
        let json = serde_json::to_string_pretty(receipt)
            .map_err(|e| std::io::Error::other(format!("serialize receipt: {e}")))?;
        let path = self
            .receipts_dir()
            .join(format!("{}-{}.json", safe_name, receipt.file));
        Self::write_atomic(&path, json.as_bytes())?;
        Ok(path)
    }
}
