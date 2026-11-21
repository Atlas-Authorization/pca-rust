//! Publish a fully written temp file over its destination so the replacement survives a crash.
//!
//! Unix: a plain rename, exactly as before. Windows cannot flush a directory, so the rename itself is made write-through:
//! `MoveFileExW(.., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` does not return until the move is on disk.
//! The caller still flushes the temp file (`File::sync_all`, which is `FlushFileBuffers`) before calling this.

use std::path::Path;

/// Flush the directory entry of `path` after a replace. Unix only; on Windows the write-through rename already did it.
pub(crate) fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        return std::fs::File::open(dir)?.sync_all();
    }
    let _ = path;
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn replace_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::rename(src, dst)
}

#[cfg(windows)]
pub(crate) fn replace_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let wide = |p: &Path| p.as_os_str().encode_wide().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (s, d) = (wide(src), wide(dst));
    // SAFETY: both buffers are NUL-terminated UTF-16 that outlive the call.
    let ok = unsafe { MoveFileExW(s.as_ptr(), d.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::replace_file;

    #[test]
    fn replaces_an_existing_file_and_removes_the_source() {
        let d = std::env::temp_dir().join(format!("durable-rename-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (src, dst) = (d.join("a.tmp"), d.join("a.json"));
        std::fs::write(&dst, "old").unwrap();
        std::fs::write(&src, "new").unwrap();
        replace_file(&src, &dst).unwrap();
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "new");
        assert!(!src.exists());
        assert!(replace_file(&d.join("missing"), &dst).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
