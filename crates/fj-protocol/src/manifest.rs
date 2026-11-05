//! Manifest: the file list a sender offers. Strict validation — a bad
//! manifest aborts the session (PATH_REJECTED); the glue NEVER writes
//! outside the output directory.

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, Result, err};
use crate::{
    CHUNK_SIZE_DEFAULT, CHUNK_SIZE_LARGE, MAX_FILES, MAX_NAME_BYTES, MAX_PATH_BYTES,
    PROTOCOL_VERSION,
};

/// Per-file compression policy. `Auto` is resolved to a boolean by the glue
/// BEFORE the manifest is built (probe: compress 4 sample chunks in memory,
/// ratio < 0.9 -> on); manifests sent on the wire carry the resolved value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GzipPolicy {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "on")]
    On,
    #[serde(rename = "off")]
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    pub id: u16,
    pub name: String,
    /// Subdirectory path "" or "a/b" (validated components).
    #[serde(default)]
    pub path: String,
    pub size: u64,
    pub chunks: u64,
    pub chunk_size: u32,
    /// hex64 SHA-256 of the full file.
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub v: u8,
    /// hex32 session id.
    pub sid: String,
    pub epoch: u32,
    pub gzip: GzipPolicy,
    pub files: Vec<FileEntry>,
    pub total: u64,
}

/// Input for building a manifest entry (glue provides these; sha256 must be
/// computed over the real file content).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileSpec {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// Resolved per-file compression decision (true = compress chunks).
    pub gzip: bool,
}

pub fn chunks_for(size: u64, chunk_size: u32) -> u64 {
    if size == 0 {
        0
    } else {
        size.div_ceil(chunk_size as u64)
    }
}

/// Build a manifest from specs (ids assigned 0..n in order).
pub fn build_manifest(
    sid: &[u8; 16],
    epoch: u32,
    specs: &[FileSpec],
    chunk_size: u32,
) -> Result<Manifest> {
    if specs.len() > MAX_FILES {
        return err(
            ErrorCode::PathRejected,
            format!("too many files ({} > {MAX_FILES})", specs.len()),
        );
    }
    if chunk_size != CHUNK_SIZE_DEFAULT && chunk_size != CHUNK_SIZE_LARGE {
        return err(
            ErrorCode::PathRejected,
            format!("unsupported chunk_size {chunk_size}"),
        );
    }
    let mut files = Vec::with_capacity(specs.len());
    let mut total = 0u64;
    for (i, s) in specs.iter().enumerate() {
        if i > u16::MAX as usize {
            return err(ErrorCode::PathRejected, "file id overflows u16");
        }
        validate_name(&s.name)?;
        validate_path(&s.path)?;
        validate_sha256(&s.sha256)?;
        let chunks = chunks_for(s.size, chunk_size);
        if chunks > u32::MAX as u64 {
            return err(ErrorCode::PathRejected, "file too large for chunk indexing");
        }
        total = total.saturating_add(s.size);
        files.push(FileEntry {
            id: i as u16,
            name: s.name.clone(),
            path: s.path.clone(),
            size: s.size,
            chunks,
            chunk_size,
            sha256: s.sha256.to_lowercase(),
        });
    }
    let gzip_any = specs.iter().any(|s| s.gzip);
    Ok(Manifest {
        v: PROTOCOL_VERSION,
        sid: hex::encode(sid),
        epoch,
        gzip: if gzip_any {
            GzipPolicy::On
        } else {
            GzipPolicy::Off
        },
        files,
        total,
    })
}

impl Manifest {
    /// Full strict validation. Rejects malformed/malicious manifests.
    pub fn validate(&self) -> Result<()> {
        if self.v != PROTOCOL_VERSION {
            return err(ErrorCode::ProtoVersion, "manifest version mismatch");
        }
        crate::envelope::parse_sid(&self.sid).map_err(|_| {
            crate::error::Error::new(ErrorCode::PathRejected, "manifest sid invalid")
        })?;
        if self.files.len() > MAX_FILES {
            return err(ErrorCode::PathRejected, "too many files in manifest");
        }
        let mut ids = std::collections::HashSet::with_capacity(self.files.len());
        let mut total = 0u64;
        for f in &self.files {
            if !ids.insert(f.id) {
                return err(
                    ErrorCode::PathRejected,
                    format!("duplicate file id {}", f.id),
                );
            }
            validate_name(&f.name)?;
            validate_path(&f.path)?;
            validate_sha256(&f.sha256)?;
            if f.chunk_size != CHUNK_SIZE_DEFAULT && f.chunk_size != CHUNK_SIZE_LARGE {
                return err(
                    ErrorCode::PathRejected,
                    format!("bad chunk_size {}", f.chunk_size),
                );
            }
            let expect = chunks_for(f.size, f.chunk_size);
            if f.chunks != expect {
                return err(
                    ErrorCode::PathRejected,
                    format!("file {} chunks {} != expected {expect}", f.id, f.chunks),
                );
            }
            total = total.saturating_add(f.size);
        }
        if self.total != total {
            return err(ErrorCode::PathRejected, "manifest total mismatch");
        }
        Ok(())
    }

    pub fn file(&self, id: u16) -> Option<&FileEntry> {
        self.files.iter().find(|f| f.id == id)
    }

    /// Relative output path "path/name" for a validated file.
    pub fn rel_path(&self, id: u16) -> Result<String> {
        let f = self.file(id).ok_or_else(|| {
            crate::error::Error::new(ErrorCode::ProtoMalformed, format!("unknown file id {id}"))
        })?;
        if f.path.is_empty() {
            Ok(f.name.clone())
        } else {
            Ok(format!("{}/{}", f.path, f.name))
        }
    }
}

/// File name rules: 1..=255 UTF-8 bytes, no '/', '\', NUL, control chars
/// (< 0x20), not "." or "..".
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return err(ErrorCode::PathRejected, "empty file name");
    }
    if name.len() > MAX_NAME_BYTES {
        return err(ErrorCode::PathRejected, "file name over 255 bytes");
    }
    if name == "." || name == ".." {
        return err(ErrorCode::PathRejected, "file name is a dot component");
    }
    for b in name.bytes() {
        if b == b'/' || b == b'\\' || b == 0 || b < 0x20 {
            return err(ErrorCode::PathRejected, "illegal byte in file name");
        }
    }
    Ok(())
}

/// Path rules: empty, or '/'-separated components each valid as a name,
/// total <= 1024 bytes, no leading '/', no ".." component.
pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    if path.len() > MAX_PATH_BYTES {
        return err(ErrorCode::PathRejected, "path over 1024 bytes");
    }
    if path.starts_with('/') || path.ends_with('/') {
        return err(
            ErrorCode::PathRejected,
            "path must be relative without edge separators",
        );
    }
    if path.contains('\\') {
        return err(ErrorCode::PathRejected, "backslash in path");
    }
    for comp in path.split('/') {
        validate_name(comp).map_err(|_| {
            crate::error::Error::new(
                ErrorCode::PathRejected,
                format!("bad path component {comp:?}"),
            )
        })?;
    }
    Ok(())
}

pub fn validate_sha256(s: &str) -> Result<()> {
    let ok = s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        err(
            ErrorCode::PathRejected,
            "sha256 must be 64 lowercase hex chars",
        )
    }
}
