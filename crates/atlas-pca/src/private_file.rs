//! Files and directories that hold secrets are owner-only on every platform, from the moment they exist.
//!
//! Unix: created with mode 0600 (files) or 0700 (directories) in the creating call, never fixed up with a chmod afterwards.
//! Windows: right after creation, and before any secret byte is written, a protected DACL with a single allow entry for the
//! current user replaces the inherited one (directories carry it to what is created inside them).

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Open `path` with `opts`, owner-only. The caller sets read/write/create/truncate on `opts`.
pub(crate) fn open_private(opts: &mut OpenOptions, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).open(path)
    }
    #[cfg(windows)]
    {
        let f = opts.open(path)?;
        win::restrict_handle(&f)?;
        Ok(f)
    }
    #[cfg(not(any(unix, windows)))]
    {
        opts.open(path)
    }
}

/// Create (or truncate) `path` owner-only and write `bytes` into it.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = open_private(OpenOptions::new().write(true).create(true).truncate(true), path)?;
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
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;
    if existed {
        tighten_dir(dir)?;
    } else {
        #[cfg(windows)]
        win::restrict_dir(dir)?;
    }
    Ok(())
}

#[cfg(unix)]
fn tighten_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn tighten_dir(dir: &Path) -> io::Result<()> {
    win::restrict_dir(dir)
}

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
    #[cfg(not(unix))]
    {
        std::fs::create_dir(dir)?;
        #[cfg(windows)]
        win::restrict_dir(dir)?;
        Ok(())
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::ptr::null_mut;

    type Handle = *mut c_void;

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(token: Handle, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
        fn GetLengthSid(sid: *const c_void) -> u32;
        fn InitializeAcl(acl: *mut c_void, len: u32, revision: u32) -> i32;
        fn AddAccessAllowedAceEx(acl: *mut c_void, revision: u32, flags: u32, mask: u32, sid: *const c_void) -> i32;
        fn SetSecurityInfo(h: Handle, ty: u32, info: u32, owner: *const c_void, group: *const c_void, dacl: *const c_void, sacl: *const c_void) -> u32;
        fn SetNamedSecurityInfoW(name: *const u16, ty: u32, info: u32, owner: *const c_void, group: *const c_void, dacl: *const c_void, sacl: *const c_void) -> u32;
        #[cfg(test)]
        fn GetNamedSecurityInfoW(name: *const u16, ty: u32, info: u32, owner: *mut *mut c_void, group: *mut *mut c_void, dacl: *mut *mut c_void, sacl: *mut *mut c_void, sd: *mut *mut c_void) -> u32;
        #[cfg(test)]
        fn GetSecurityDescriptorControl(sd: *const c_void, control: *mut u16, revision: *mut u32) -> i32;
        #[cfg(test)]
        fn GetAclInformation(acl: *const c_void, info: *mut c_void, len: u32, class: u32) -> i32;
        #[cfg(test)]
        fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> i32;
        #[cfg(test)]
        fn EqualSid(a: *const c_void, b: *const c_void) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        #[cfg(test)]
        fn LocalFree(p: *mut c_void) -> *mut c_void;
    }

    const TOKEN_QUERY: u32 = 0x8;
    const TOKEN_USER_CLASS: u32 = 1;
    const ACL_REVISION: u32 = 2;
    const FILE_ALL_ACCESS: u32 = 0x1F_01FF;
    const OBJECT_INHERIT_ACE: u32 = 0x1;
    const CONTAINER_INHERIT_ACE: u32 = 0x2;
    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x4;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

    fn last() -> io::Error {
        io::Error::last_os_error()
    }

    /// The current user's TOKEN_USER, in an 8-byte aligned buffer whose first field points at the SID inside the same buffer.
    fn token_user() -> io::Result<Vec<u64>> {
        let mut buf = vec![0u64; 128]; // 1 KiB; a SID is at most 68 bytes
        let mut tok: Handle = null_mut();
        // SAFETY: plain out-parameters that outlive the calls; the token handle is closed before returning.
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
                return Err(last());
            }
            let mut ret = 0u32;
            let ok = GetTokenInformation(tok, TOKEN_USER_CLASS, buf.as_mut_ptr() as *mut c_void, (buf.len() * 8) as u32, &mut ret);
            let e = if ok == 0 { Some(last()) } else { None };
            CloseHandle(tok);
            if let Some(e) = e {
                return Err(e);
            }
        }
        Ok(buf)
    }

    fn sid_of(tu: &[u64]) -> *const c_void {
        // SAFETY: TOKEN_USER begins with the SID pointer, and the buffer is 8-byte aligned.
        unsafe { *(tu.as_ptr() as *const *const c_void) }
    }

    /// An ACL holding exactly one entry: allow everything to the current user.
    fn owner_only_acl(inherit: bool) -> io::Result<Vec<u32>> {
        let tu = token_user()?;
        let sid = sid_of(&tu);
        // SAFETY: `sid` points into `tu`, which lives to the end of this function; the ACL buffer is sized for header + one ACE.
        unsafe {
            let sid_len = GetLengthSid(sid) as usize;
            let bytes = (8 + 8 + sid_len + 3) / 4 * 4 + 8;
            let mut acl = vec![0u32; bytes / 4];
            if InitializeAcl(acl.as_mut_ptr() as *mut c_void, bytes as u32, ACL_REVISION) == 0 {
                return Err(last());
            }
            let flags = if inherit { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE } else { 0 };
            if AddAccessAllowedAceEx(acl.as_mut_ptr() as *mut c_void, ACL_REVISION, flags, FILE_ALL_ACCESS, sid) == 0 {
                return Err(last());
            }
            Ok(acl)
        }
    }

    fn code(rc: u32) -> io::Result<()> {
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(rc as i32))
        }
    }

    const INFO: u32 = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;

    pub fn restrict_handle(f: &File) -> io::Result<()> {
        let acl = owner_only_acl(false)?;
        // SAFETY: a live file handle and a well-formed ACL.
        code(unsafe { SetSecurityInfo(f.as_raw_handle() as Handle, SE_FILE_OBJECT, INFO, null_mut(), null_mut(), acl.as_ptr() as *const c_void, null_mut()) })
    }

    pub fn restrict_dir(dir: &Path) -> io::Result<()> {
        let acl = owner_only_acl(true)?;
        let w = wide(dir);
        // SAFETY: NUL-terminated path and a well-formed ACL.
        code(unsafe { SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, INFO, null_mut(), null_mut(), acl.as_ptr() as *const c_void, null_mut()) })
    }

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Read the DACL back: protected, one entry, an allow for the current user.
    #[cfg(test)]
    pub fn owner_only(path: &Path) -> io::Result<bool> {
        let tu = token_user()?;
        let w = wide(path);
        // SAFETY: out-parameters live across the calls; the security descriptor is freed once the answer is computed.
        unsafe {
            let (mut dacl, mut sd): (*mut c_void, *mut c_void) = (null_mut(), null_mut());
            code(GetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), &mut dacl, null_mut(), &mut sd))?;
            let (mut ctrl, mut rev) = (0u16, 0u32);
            let ok_ctrl = GetSecurityDescriptorControl(sd, &mut ctrl, &mut rev) != 0;
            let mut info = [0u32; 3]; // ACL_SIZE_INFORMATION: AceCount, AclBytesInUse, AclBytesFree
            let ok_info = GetAclInformation(dacl, info.as_mut_ptr() as *mut c_void, 12, 2) != 0;
            let mut ace: *mut c_void = null_mut();
            let ok_ace = ok_info && info[0] >= 1 && GetAce(dacl, 0, &mut ace) != 0;
            let mine = ok_ace && *(ace as *const u8) == 0 && EqualSid((ace as *const u8).add(8) as *const c_void, sid_of(&tu)) != 0;
            LocalFree(sd);
            const SE_DACL_PROTECTED: u16 = 0x1000;
            Ok(ok_ctrl && ctrl & SE_DACL_PROTECTED != 0 && ok_info && info[0] == 1 && mine)
        }
    }
}

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
        let mut f = open_private(OpenOptions::new().write(true).create_new(true), &p).unwrap();
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
