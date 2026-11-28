//! Files and directories that hold secrets are owner-only on every platform, from the moment they exist.
//!
//! Unix: created with mode 0600 (files) or 0700 (directories) in the creating call, never fixed up with a chmod afterwards.
//! Windows: right after creation, and before any secret byte is written, a protected DACL with a single allow entry for the
//! current user replaces the inherited one (directories carry it to what is created inside them).

use std::fs::File;
use std::io;
use std::path::Path;

/// How a private file is created.
#[derive(Clone, Copy)]
pub(crate) enum Create {
    /// Fail if it exists (`create_new`).
    New,
    /// Create it, or empty an existing one (`create` + `truncate`).
    Truncate,
}

/// Open `path` for writing, owner-only.
pub(crate) fn open_private(how: Create, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).mode(0o600);
        match how {
            Create::New => o.create_new(true),
            Create::Truncate => o.create(true).truncate(true),
        };
        o.open(path)
    }
    #[cfg(windows)]
    {
        win::create_file(how, path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true);
        match how {
            Create::New => o.create_new(true),
            Create::Truncate => o.create(true).truncate(true),
        };
        o.open(path)
    }
}

/// Create (or truncate) `path` owner-only and write `bytes` into it.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = open_private(Create::Truncate, path)?;
    f.write_all(bytes)
}

/// `create_dir_all`, with every directory this call creates owner-only. A final directory that already exists is tightened to
/// owner-only too (0700; on Windows the protected single-owner DACL); if that fails the error is returned, so secrets are never
/// written into a directory that stayed loose.
pub(crate) fn create_dir_all_private(dir: &Path) -> io::Result<()> {
    let existed = dir.is_dir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    #[cfg(windows)]
    win::create_dir_all(dir)?;
    #[cfg(not(any(unix, windows)))]
    std::fs::create_dir_all(dir)?;
    if existed {
        tighten_dir(dir)?;
    }
    Ok(())
}

#[cfg(unix)]
fn tighten_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
use win::restrict_dir as tighten_dir;

#[cfg(not(any(unix, windows)))]
fn tighten_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// `create_dir` (one level, fails if it exists), owner-only.
pub(crate) fn create_dir_private(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(windows)]
    {
        win::create_dir(dir)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir(dir)
    }
}

// the Windows arm lives in its own file so the Windows-only mutation slice mutates exactly the code Windows compiles
#[cfg(windows)]
#[path = "private_file_windows.rs"]
mod win;

/// Test support: assert that `path` (file or directory) is owner-only, reading the restriction back from the file system.
#[cfg(test)]
pub(crate) fn assert_owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let want = if path.is_dir() { 0o700 } else { 0o600 };
        assert_eq!(m, want, "{} is {:o}", path.display(), m);
    }
    #[cfg(windows)]
    assert!(win::owner_only(path).unwrap(), "{} is not a protected single-entry DACL for the current user", path.display());
    #[cfg(not(any(unix, windows)))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("private-file-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_created_file_is_owner_only_before_it_is_written() {
        let d = scratch("file");
        create_dir_all_private(&d).unwrap();
        let p = d.join("k.pem");
        let mut f = open_private(Create::New, &p).unwrap();
        assert_owner_only(&p);
        std::io::Write::write_all(&mut f, b"secret").unwrap();
        drop(f);
        assert_owner_only(&p);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn write_private_creates_and_rewrites_owner_only() {
        let d = scratch("write");
        create_dir_all_private(&d).unwrap();
        let p = d.join("w.bin");
        write_private(&p, b"one").unwrap();
        write_private(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_owner_only(&p);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_pre_existing_loose_directory_is_tightened() {
        let d = scratch("loose");
        std::fs::create_dir_all(&d).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        create_dir_all_private(&d).unwrap();
        assert_owner_only(&d);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn created_directories_are_owner_only() {
        let d = scratch("dir");
        let deep = d.join("a").join("b");
        create_dir_all_private(&deep).unwrap();
        assert_owner_only(&deep);
        let one = d.join("one");
        create_dir_private(&one).unwrap();
        assert_owner_only(&one);
        assert!(create_dir_private(&one).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
