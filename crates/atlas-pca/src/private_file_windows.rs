//! Windows arm of the private files: protected single-owner DACLs, set in the creating call or over an existing object.
//! Its own file so the Windows-only mutation slice mutates exactly the code Windows compiles.

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
// OBJECT_INHERIT_ACE (0x1) | CONTAINER_INHERIT_ACE (0x2), written as one value: the two bits are disjoint, so an operator between
// them (| vs ^) could not change the entry
const INHERIT_TO_CHILDREN: u32 = 0x3;
// sizeof(ACL) (8) + ACCESS_ALLOWED_ACE up to its SidStart (8); a SID is 8 bytes + 4 per sub-authority, so header + SID is DWORD
// aligned and needs no rounding
const ACL_AND_ACE_HEADERS: usize = 16;
const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;

fn last() -> io::Error {
    io::Error::last_os_error()
}

/// A Win32 BOOL result: nonzero is success, zero leaves the error in GetLastError. Every BOOL call goes through here, as a
/// whole statement (`win32(..)?;`), so dropping that statement drops the call itself, never only its error path.
fn win32(r: i32) -> io::Result<()> {
    if r == 0 {
        Err(last())
    } else {
        Ok(())
    }
}

/// The current user's TOKEN_USER, in an 8-byte aligned buffer whose first field points at the SID inside the same buffer.
fn token_user() -> io::Result<Vec<u64>> {
    let mut buf = vec![0u64; 128]; // 1 KiB; a SID is at most 68 bytes
    let len = std::mem::size_of_val(buf.as_slice()) as u32;
    let mut tok: Handle = null_mut();
    // SAFETY: plain out-parameters that outlive the calls; the token handle is closed before returning.
    unsafe {
        win32(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok))?;
        let mut ret = 0u32;
        let r = win32(GetTokenInformation(tok, TOKEN_USER_CLASS, buf.as_mut_ptr() as *mut c_void, len, &mut ret));
        CloseHandle(tok);
        r.map(|()| buf)
    }
}

fn sid_of(tu: &[u64]) -> *const c_void {
    // SAFETY: TOKEN_USER begins with the SID pointer, and the buffer is 8-byte aligned.
    unsafe { *(tu.as_ptr() as *const *const c_void) }
}

/// An ACL holding exactly one entry, sized to fit it exactly: allow everything to the current user.
fn owner_only_acl(inherit: bool) -> io::Result<Vec<u32>> {
    let tu = token_user()?;
    let sid = sid_of(&tu);
    // SAFETY: `sid` points into `tu`, which lives to the end of this function; the ACL buffer holds `bytes` (header + one ACE).
    unsafe {
        let sid_len = GetLengthSid(sid) as usize;
        let bytes = ACL_AND_ACE_HEADERS + sid_len;
        let mut acl = vec![0u32; bytes.div_ceil(4)];
        win32(InitializeAcl(acl.as_mut_ptr() as *mut c_void, bytes as u32, ACL_REVISION))?;
        let flags = if inherit { INHERIT_TO_CHILDREN } else { 0 };
        win32(AddAccessAllowedAceEx(acl.as_mut_ptr() as *mut c_void, ACL_REVISION, flags, FILE_ALL_ACCESS, sid))?;
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

// DACL_SECURITY_INFORMATION (0x4) | PROTECTED_DACL_SECURITY_INFORMATION (0x8000_0000), one literal: the bits are disjoint, so `|` and `^` agree
const INFO: u32 = 0x8000_0004;

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
            win32(InitializeSecurityDescriptor(sdp, SECURITY_DESCRIPTOR_REVISION))?;
            win32(SetSecurityDescriptorDacl(sdp, 1, acl.as_mut_ptr() as *const c_void, 0))?;
            win32(SetSecurityDescriptorControl(sdp, SE_DACL_PROTECTED, SE_DACL_PROTECTED))?;
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

/// `CreateDirectoryW` with the protected descriptor; an existing directory is an `AlreadyExists` error (std maps
/// ERROR_ALREADY_EXISTS to that kind).
pub fn create_dir(dir: &Path) -> io::Result<()> {
    let mut a = Attrs::new(true)?;
    let w = wide(dir);
    // SAFETY: NUL-terminated path and a live SECURITY_ATTRIBUTES.
    win32(unsafe { CreateDirectoryW(w.as_ptr(), &mut a.sa) })
}

/// Every missing directory on the way down to `dir` is created owner-only.
pub fn create_dir_all(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_dir_all(parent)?;
    }
    existing_dir_is_ok(create_dir(dir), dir)
}

/// A create that lost a race to another creator of the same directory succeeded; anything else (a file in the way) is the error.
fn existing_dir_is_ok(r: io::Result<()>, dir: &Path) -> io::Result<()> {
    match r {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory that inherits the temp directory's (several, unprotected) entries: loose.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("private-file-win-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// (AceCount, AclBytesFree, the first entry's AceFlags) of an ACL buffer.
    fn acl_shape(acl: &[u32]) -> (u32, u32, u8) {
        // SAFETY: `acl` is a buffer InitializeAcl filled; the out-parameters live across the calls.
        unsafe {
            let mut info = [0u32; 3]; // ACL_SIZE_INFORMATION: AceCount, AclBytesInUse, AclBytesFree
            assert!(GetAclInformation(acl.as_ptr() as *const c_void, info.as_mut_ptr() as *mut c_void, 12, 2) != 0);
            let mut ace: *mut c_void = null_mut();
            assert!(GetAce(acl.as_ptr() as *const c_void, 0, &mut ace) != 0);
            (info[0], info[2], *(ace as *const u8).add(1))
        }
    }

    #[test]
    fn the_acl_is_one_exactly_fitting_entry_that_only_directories_pass_on() {
        assert_eq!(acl_shape(&owner_only_acl(true).unwrap()), (1, 0, INHERIT_TO_CHILDREN as u8));
        assert_eq!(acl_shape(&owner_only_acl(false).unwrap()), (1, 0, 0));
    }

    #[test]
    fn a_pre_existing_loose_file_is_narrowed_before_it_is_rewritten() {
        let d = scratch("loosefile");
        let p = d.join("k.bin");
        std::fs::write(&p, b"old secret").unwrap();
        assert!(!owner_only(&p).unwrap(), "the fixture must start loose");
        super::super::write_private(&p, b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        assert!(owner_only(&p).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn create_new_refuses_an_existing_file_and_leaves_it_alone() {
        let d = scratch("new");
        let p = d.join("k.pem");
        std::fs::write(&p, b"keep").unwrap();
        assert_eq!(create_file(super::super::Create::New, &p).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&p).unwrap(), b"keep");
        assert!(!owner_only(&p).unwrap(), "a refused create leaves the existing descriptor alone");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_restriction_that_fails_is_an_error() {
        let d = scratch("missing");
        assert!(restrict_file(&d.join("none")).is_err());
        assert!(restrict_dir(&d.join("none")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_an_existing_directory_excuses_already_exists() {
        let d = scratch("exists");
        let f = d.join("file");
        std::fs::write(&f, b"").unwrap();
        let exists = || Err(io::Error::from(io::ErrorKind::AlreadyExists));
        assert!(existing_dir_is_ok(exists(), &d).is_ok());
        assert_eq!(existing_dir_is_ok(exists(), &f).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(existing_dir_is_ok(Err(io::Error::from(io::ErrorKind::NotFound)), &d).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(existing_dir_is_ok(Ok(()), &f).is_ok());
        // end to end: a file in the way fails, and CreateDirectoryW over an existing directory is AlreadyExists
        assert_eq!(create_dir_all(&f).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(create_dir(&d).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        let _ = std::fs::remove_dir_all(&d);
    }
}
