//! A file-backed SCITT log store: one append-only file of checksummed transactions (entry plus its new subtree hashes), synced
//! before `append` returns, so a crash leaves the whole transaction or none of it. The file format is byte-identical to the
//! reference store. A torn final record is discarded on open; corruption anywhere else is `store_corrupt`.
//!
//! SINGLE PROCESS: the file is not locked, so run one writer per file (use a database-backed store for a fleet). Memory use is the
//! 32-byte hash of every subtree plus one offset per entry; entry bytes are read from disk on demand.
//!
//! Record: `u32be len | payload | sha256(payload)`, payload = `u32be entryLen | entry | u16be count | count x (u8 level | u32be index | 3 zero bytes | 32-byte hash)`.
use crate::scitt::{ScittLogError, ScittLogStore, StoredNode};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

pub struct FileScittLogStore {
    file: Mutex<File>,
    nodes: HashMap<(u8, u32), [u8; 32]>,
    offsets: Vec<(u64, usize)>,
    end: u64,
}

fn corrupt(message: impl Into<String>) -> ScittLogError {
    ScittLogError { code: "store_corrupt", message: message.into() }
}

fn io_err(e: std::io::Error) -> ScittLogError {
    ScittLogError { code: "", message: e.to_string() }
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl FileScittLogStore {
    /// Open (creating if absent) the log file at `path` and rebuild the index.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ScittLogError> {
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).map_err(io_err)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(io_err)?;
        let mut s = FileScittLogStore { file: Mutex::new(file), nodes: HashMap::new(), offsets: Vec::new(), end: 0 };
        s.load(&buf)?;
        Ok(s)
    }

    fn load(&mut self, buf: &[u8]) -> Result<(), ScittLogError> {
        let total = buf.len() as i64;
        let mut pos: i64 = 0;
        while pos < total {
            let p = pos as usize;
            // the reference reads up to 4 bytes; a short head reads as length -1
            let len: i64 = if buf.len() - p >= 4 { be32(buf, p) as i64 } else { -1 };
            let rec_end = pos + 4 + len + 32;
            if len < 6 || rec_end > total {
                return self.discard_tail(pos, rec_end > total);
            }
            let payload = &buf[p + 4..p + 4 + len as usize];
            let sum = &buf[p + 4 + len as usize..rec_end as usize];
            if Sha256::digest(payload).as_slice() != sum {
                return self.discard_tail(pos, rec_end == total);
            }
            let entry_len = be32(payload, 0) as usize;
            let q = 4 + entry_len;
            // the reference's readUInt16BE throws a RangeError past the payload
            if q + 2 > payload.len() {
                return Err(ScittLogError { code: "", message: "the record entry length is out of range".into() });
            }
            let count = u16::from_be_bytes([payload[q], payload[q + 1]]) as usize;
            let mut q = q + 2;
            if q + count * 40 != payload.len() {
                return Err(corrupt("a log record has an inconsistent length"));
            }
            self.offsets.push((p as u64 + 8, entry_len));
            for _ in 0..count {
                let mut h = [0u8; 32];
                h.copy_from_slice(&payload[q + 8..q + 40]);
                self.nodes.insert((payload[q], be32(payload, q + 1)), h);
                q += 40;
            }
            pos = rec_end;
        }
        self.end = pos as u64;
        Ok(())
    }

    fn discard_tail(&mut self, pos: i64, is_tail: bool) -> Result<(), ScittLogError> {
        if !is_tail {
            return Err(corrupt(format!("the log file is corrupt at offset {pos}")));
        }
        let f = self.file.lock().map_err(|_| corrupt("the log file lock is poisoned"))?;
        f.set_len(pos as u64).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
        drop(f);
        self.end = pos as u64;
        Ok(())
    }

    /// `append` with the reference's errors: a malformed node is `store_corrupt`; a write failure leaves the file as it was.
    pub fn try_append(&mut self, expected_size: u64, entry: &[u8], nodes: &[StoredNode]) -> Result<bool, ScittLogError> {
        if self.offsets.len() as u64 != expected_size {
            return Ok(false);
        }
        for n in nodes {
            if n.level > 255 || n.index > 0xffff_ffff || n.hash.len() != 32 {
                return Err(corrupt("a subtree node is malformed"));
            }
        }
        if entry.len() > u32::MAX as usize || nodes.len() > u16::MAX as usize {
            return Err(corrupt("a log record is too large"));
        }
        let mut payload = Vec::with_capacity(4 + entry.len() + 2 + nodes.len() * 40);
        payload.extend_from_slice(&(entry.len() as u32).to_be_bytes());
        payload.extend_from_slice(entry);
        payload.extend_from_slice(&(nodes.len() as u16).to_be_bytes());
        for n in nodes {
            payload.push(n.level as u8);
            payload.extend_from_slice(&(n.index as u32).to_be_bytes());
            payload.extend_from_slice(&[0, 0, 0]);
            payload.extend_from_slice(&n.hash);
        }
        let mut record = Vec::with_capacity(payload.len() + 36);
        record.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        record.extend_from_slice(&payload);
        record.extend_from_slice(&Sha256::digest(&payload));
        {
            let mut f = self.file.lock().map_err(|_| corrupt("the log file lock is poisoned"))?;
            let written = f.seek(SeekFrom::Start(self.end)).and_then(|_| f.write_all(&record)).and_then(|_| f.sync_all());
            if let Err(e) = written {
                let _ = f.set_len(self.end); // never leave a half record behind
                return Err(io_err(e));
            }
        }
        self.offsets.push((self.end + 8, entry.len()));
        for n in nodes {
            let mut h = [0u8; 32];
            h.copy_from_slice(&n.hash);
            self.nodes.insert((n.level as u8, n.index as u32), h);
        }
        self.end += record.len() as u64;
        Ok(true)
    }
}

impl ScittLogStore for FileScittLogStore {
    fn size(&self) -> i64 {
        self.offsets.len() as i64
    }

    fn get_entry(&self, index: u64) -> Option<Vec<u8>> {
        let (at, len) = *self.offsets.get(usize::try_from(index).ok()?)?;
        let mut f = self.file.lock().ok()?;
        let mut out = vec![0u8; len];
        f.seek(SeekFrom::Start(at)).ok()?;
        f.read_exact(&mut out).ok()?;
        Some(out)
    }

    fn get_node(&self, level: u32, index: u64) -> Option<Vec<u8>> {
        self.nodes.get(&(u8::try_from(level).ok()?, u32::try_from(index).ok()?)).map(|h| h.to_vec())
    }

    /// The trait cannot raise: a refused or failed append is `false` (fail closed); use [`Self::try_append`] for the reason.
    fn append(&mut self, expected_size: u64, entry: &[u8], nodes: &[StoredNode]) -> bool {
        self.try_append(expected_size, entry, nodes).unwrap_or(false)
    }
}
