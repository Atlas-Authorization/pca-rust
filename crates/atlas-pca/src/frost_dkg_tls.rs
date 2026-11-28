//! Length-prefixed framing for a DKG link (the TLS transport's wire format): a 4-byte big-endian payload length followed by the payload. A
//! decoder refuses a frame whose declared length exceeds the message cap BEFORE buffering it, so a hostile peer cannot make a node allocate a
//! gigabyte. The transport itself (mutual TLS 1.3 pinned by certificate) is the host's; this is the framing loop only.
use crate::frost_dkg_channel::DKG_MAX_MESSAGE_BYTES;

/// `len(payload)` as 4 big-endian bytes, then the payload. `Err` for a payload longer than a 32-bit length can carry.
pub fn frame_encode(payload: &[u8]) -> Result<Vec<u8>, String> {
    let n = u32::try_from(payload.len()).map_err(|_| "frame payload exceeds 4 GiB".to_string())?;
    Ok([n.to_be_bytes().as_slice(), payload].concat())
}

/// Incremental frame reader: [`FrameDecoder::feed`] appends bytes and returns the complete payloads now available. After a frame over the cap
/// `error` is `Some("oversize")` and every later chunk is ignored; `buffered` is the number of bytes held for an unfinished frame.
pub struct FrameDecoder {
    max: usize,
    buf: Vec<u8>,
    pub error: Option<String>,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new(DKG_MAX_MESSAGE_BYTES)
    }
}

impl FrameDecoder {
    pub fn new(max_frame: usize) -> Self {
        FrameDecoder { max: max_frame, buf: Vec::new(), error: None }
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.error.is_some() {
            return out;
        }
        self.buf.extend_from_slice(chunk);
        while self.buf.len() >= 4 {
            let n = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
            if n > self.max {
                self.error = Some("oversize".into());
                break;
            }
            if self.buf.len() < 4 + n {
                break;
            }
            out.push(self.buf[4..4 + n].to_vec());
            self.buf.drain(..4 + n);
        }
        out
    }
}
