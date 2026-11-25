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
    #[cfg(windows)]
    {
        win::create_dir(dir)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir(dir)
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    type Handle = *mut c_void;

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(token: Handle, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
        fn GetLengthSid(sid: *const c_void) -> u32;
        fn InitializeSecurityDescriptor(sd: *mut c_void, revision: u32) -> i32;
        fn SetSecurityDescriptorDacl(sd: *mut c_void, present: i32, dacl: *const c_void, defaulted: i32) -> i32;
        fn SetSecurityDescriptorControl(sd: *mut c_void, mask: u16, set: u16) -> i32;
        fn InitializeAcl(acl: *mut c_void, len: u32, revision: u32) -> i32;
        fn AddAccessAllowedAceEx(acl: *mut c_void, revision: u32, flags: u32, mask: u32, sid: *const c_void) -> i32;
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
        fn CreateFileW(name: *const u16, access: u32, share: u32, sa: *mut SecurityAttributes, disposition: u32, flags: u32, template: Handle) -> Handle;
        fn CreateDirectoryW(name: *const u16, sa: *mut SecurityAttributes) -> i32;
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

    pub fn restrict_file(path: &Path) -> io::Result<()> {
        set_named(path, false)
    }

    pub fn restrict_dir(dir: &Path) -> io::Result<()> {
        set_named(dir, true)
    }

    fn set_named(path: &Path, inherit: bool) -> io::Result<()> {
        let acl = owner_only_acl(inherit)?;
        let w = wide(path);
        // SAFETY: NUL-terminated path and a well-formed ACL.
        code(unsafe { SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, INFO, null_mut(), null_mut(), acl.as_ptr() as *const c_void, null_mut()) })
    }

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit_handle: i32,
    }

    /// A security descriptor holding the one-entry protected DACL, for the creating call itself: the object never exists with
    /// another descriptor, so no other process can open it first and keep a handle. The buffers live as long as this value.
    struct Attrs {
        _acl: Vec<u32>,
        _sd: Vec<u64>,
        sa: SecurityAttributes,
    }

    impl Attrs {
        fn new(inherit: bool) -> io::Result<Attrs> {
            const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
            const SE_DACL_PROTECTED: u16 = 0x1000;
            let mut acl = owner_only_acl(inherit)?;
            let mut sd = vec![0u64; 16]; // 128 bytes; an absolute SECURITY_DESCRIPTOR is 40
            let sdp = sd.as_mut_ptr() as *mut c_void;
            // SAFETY: `sd` is zeroed and large enough; the ACL buffer outlives the descriptor (both are kept in the result).
            unsafe {
                if InitializeSecurityDescriptor(sdp, SECURITY_DESCRIPTOR_REVISION) == 0 {
                    return Err(last());
                }
                if SetSecurityDescriptorDacl(sdp, 1, acl.as_mut_ptr() as *const c_void, 0) == 0 {
                    return Err(last());
                }
                if SetSecurityDescriptorControl(sdp, SE_DACL_PROTECTED, SE_DACL_PROTECTED) == 0 {
                    return Err(last());
                }
            }
            let sa = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32, descriptor: sdp, inherit_handle: 0 };
            Ok(Attrs { _acl: acl, _sd: sd, sa })
        }
    }

    const GENERIC_WRITE: u32 = 0x4000_0000;
    const SHARE_ALL: u32 = 0x7; // read | write | delete, as std opens
    const CREATE_NEW: u32 = 1;
    const TRUNCATE_EXISTING: u32 = 5;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const ERROR_FILE_EXISTS: i32 = 80;
    const ERROR_ALREADY_EXISTS: i32 = 183;

    fn open_raw(path: &Path, disposition: u32, sa: *mut SecurityAttributes) -> io::Result<std::fs::File> {
        use std::os::windows::io::FromRawHandle;
        let w = wide(path);
        // SAFETY: NUL-terminated path; `sa` is null or a live SECURITY_ATTRIBUTES; the handle is owned by the File on success.
        let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_WRITE, SHARE_ALL, sa, disposition, FILE_ATTRIBUTE_NORMAL, null_mut()) };
        if h as isize == -1 {
            return Err(last());
        }
        // SAFETY: a valid, owned file handle.
        Ok(unsafe { std::fs::File::from_raw_handle(h as _) })
    }

    /// Create the file with its protected owner-only descriptor in the creating call. `Truncate` over an existing file narrows
    /// that file first (its descriptor cannot be supplied at open), then empties it.
    pub fn create_file(how: super::Create, path: &Path) -> io::Result<std::fs::File> {
        let mut a = Attrs::new(false)?;
        match open_raw(path, CREATE_NEW, &mut a.sa) {
            Err(e) if matches!(how, super::Create::Truncate) && e.raw_os_error() == Some(ERROR_FILE_EXISTS) => {
                restrict_file(path)?;
                open_raw(path, TRUNCATE_EXISTING, null_mut())
            }
            r => r,
        }
    }

    /// `CreateDirectoryW` with the protected descriptor; an existing directory is an `AlreadyExists` error.
    pub fn create_dir(dir: &Path) -> io::Result<()> {
        let mut a = Attrs::new(true)?;
        let w = wide(dir);
        // SAFETY: NUL-terminated path and a live SECURITY_ATTRIBUTES.
        if unsafe { CreateDirectoryW(w.as_ptr(), &mut a.sa) } == 0 {
            let e = last();
            return Err(if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS) { io::Error::from(io::ErrorKind::AlreadyExists) } else { e });
        }
        Ok(())
    }

    /// Every missing directory on the way down to `dir` is created owner-only.
    pub fn create_dir_all(dir: &Path) -> io::Result<()> {
        if dir.is_dir() {
            return Ok(());
        }
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_dir_all(parent)?;
        }
        match create_dir(dir) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
            r => r,
        }
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
