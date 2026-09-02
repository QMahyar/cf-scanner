use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Result, anyhow};

pub fn data_write_guard() -> MutexGuard<'static, ()> {
    static WRITE_GATE: Mutex<()> = Mutex::new(());
    WRITE_GATE.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn data_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CF_SCANNER_DATA_DIR")
        && !dir.trim().is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    let dirs = directories::ProjectDirs::from("com", "qmahyar", "cf-scanner")
        .ok_or_else(|| anyhow!("could not resolve a data directory"))?;
    Ok(dirs.data_dir().to_path_buf())
}

pub fn refreshed_ranges_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("cf-ranges.txt"))
}

pub fn refreshed_ranges_v6_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("cf-ranges-v6.txt"))
}

pub fn xray_binary_path() -> Result<PathBuf> {
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    #[cfg(test)]
    if let Some(dir) = test_env::SEAM_DATA_DIR.lock().unwrap().clone() {
        return Ok(dir.join(name));
    }
    Ok(data_dir()?.join(name))
}

#[cfg(windows)]
pub fn lock_down_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows::core::PCWSTR;

    let guard = windows_security::build_owner_dacl()?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let err = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR::from_raw(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(guard.acl_ptr()),
            None,
        )
    };
    if err != NO_ERROR {
        return Err(std::io::Error::from_raw_os_error(err.0 as i32));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn lock_down_to_owner(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
mod windows_security {
    use std::io;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, GENERIC_ALL, HANDLE, NO_ERROR, WIN32_ERROR,
    };
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
        TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, GetTokenInformation, InitializeSecurityDescriptor, NO_INHERITANCE,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::PWSTR;

    fn win_err(err: WIN32_ERROR) -> io::Error {
        io::Error::from_raw_os_error(err.0 as i32)
    }

    fn hresult_err(err: windows::core::Error) -> io::Error {
        io::Error::from_raw_os_error(err.code().0)
    }

    pub(super) struct OwnedAcl {
        pub ptr: *mut ACL,
    }

    impl Drop for OwnedAcl {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe {
                    let _ = windows::Win32::Foundation::LocalFree(Some(
                        windows::Win32::Foundation::HLOCAL(self.ptr.cast()),
                    ));
                }
            }
        }
    }

    pub(super) struct OwnerDacl {
        descriptor: SECURITY_DESCRIPTOR,
        acl: OwnedAcl,
    }

    impl OwnerDacl {
        pub fn acl_ptr(&self) -> *mut ACL {
            self.acl.ptr
        }

        pub fn security_attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: &self.descriptor as *const SECURITY_DESCRIPTOR
                    as *mut core::ffi::c_void,
                bInheritHandle: windows::core::BOOL(0),
            }
        }
    }

    pub(super) fn build_owner_dacl() -> io::Result<OwnerDacl> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(hresult_err)?;
        let mut len = 0u32;
        let sized = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };
        let expected = sized
            .err()
            .map(|e| e.code() == windows::core::HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0))
            .unwrap_or(false);
        if !expected || len == 0 {
            unsafe {
                let _ = CloseHandle(token);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "token user size query failed",
            ));
        }
        let mut buf = vec![0u8; len as usize];
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                len,
                &mut len,
            )
        }
        .map_err(|e| {
            unsafe {
                let _ = CloseHandle(token);
            }
            hresult_err(e)
        })?;
        unsafe {
            let _ = CloseHandle(token);
        }
        let sid: PSID = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };

        let ea = [EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: Default::default(),
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: PWSTR(sid.0.cast()),
            },
        }];
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let err = unsafe { SetEntriesInAclW(Some(&ea), None, &mut new_acl) };
        if err != NO_ERROR {
            return Err(win_err(err));
        }
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        unsafe {
            InitializeSecurityDescriptor(
                PSECURITY_DESCRIPTOR(&mut descriptor as *mut _ as *mut _),
                1,
            )
        }
        .map_err(hresult_err)?;
        unsafe {
            SetSecurityDescriptorDacl(
                PSECURITY_DESCRIPTOR(&mut descriptor as *mut _ as *mut _),
                true,
                Some(new_acl),
                false,
            )
        }
        .map_err(hresult_err)?;
        Ok(OwnerDacl {
            descriptor,
            acl: OwnedAcl { ptr: new_acl },
        })
    }
}

#[cfg(windows)]
pub fn write_secret(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::FromRawHandle;
    use windows::Win32::Foundation::GENERIC_WRITE;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CREATEFILE2_EXTENDED_PARAMETERS, FILE_CREATION_DISPOSITION, FILE_SHARE_MODE,
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let guard = match windows_security::build_owner_dacl() {
        Ok(v) => v,
        Err(_) => {
            std::fs::File::create(path)?;
            lock_down_to_owner(path)?;
            let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
            return file.write_all(data);
        }
    };
    let sa = guard.security_attributes();

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let params = CREATEFILE2_EXTENDED_PARAMETERS {
        dwSize: std::mem::size_of::<CREATEFILE2_EXTENDED_PARAMETERS>() as u32,
        lpSecurityAttributes: &sa as *const SECURITY_ATTRIBUTES as *mut _,
        ..unsafe { std::mem::zeroed() }
    };

    let handle = unsafe {
        windows::Win32::Storage::FileSystem::CreateFile2(
            windows::core::PCWSTR::from_raw(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            FILE_CREATION_DISPOSITION(CREATE_ALWAYS.0),
            Some(&params),
        )
    };

    match handle {
        Ok(h) => {
            let file = unsafe { std::fs::File::from_raw_handle(h.0 as *mut _) };
            let _ = h;
            let mut file = file;
            file.write_all(data)?;
            file.sync_all()?;
            Ok(())
        }
        Err(_) => {
            std::fs::File::create(path)?;
            lock_down_to_owner(path)?;
            let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
            file.write_all(data)
        }
    }
}

#[cfg(not(windows))]
pub fn write_secret(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

#[cfg(test)]
pub(crate) mod test_env {

    use std::path::{Path, PathBuf};

    pub(crate) static DATA_DIR_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    pub(crate) static SEAM_DATA_DIR: std::sync::Mutex<Option<PathBuf>> =
        std::sync::Mutex::new(None);

    pub(crate) struct IsolatedDataDir {
        dir: PathBuf,
    }

    impl IsolatedDataDir {
        pub(crate) fn new() -> Self {
            let dir = std::env::temp_dir().join("cf-scanner-paths-tests");
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            unsafe { std::env::set_var("CF_SCANNER_DATA_DIR", &dir) };
            Self { dir }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.dir
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::test_env::{DATA_DIR_LOCK, IsolatedDataDir};

    #[cfg(windows)]
    #[test]
    fn lock_down_to_owner_keeps_the_file_usable_by_the_owner() {
        let dir = std::env::temp_dir().join(format!("cf-scanner-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let file = dir.join("secret.json");
        std::fs::write(&file, b"{}").unwrap();
        lock_down_to_owner(&file).expect("DACL lockdown must succeed for the owner");
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file)
            .expect("owner retains write access");
        assert_eq!(std::fs::read(&file).unwrap(), b"");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn write_secret_sets_dacl_at_creation() {
        use std::os::windows::ffi::OsStrExt as _;
        use windows::Win32::Foundation::{HLOCAL, NO_ERROR};
        use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };

        let dir =
            std::env::temp_dir().join(format!("cf-scanner-write-secret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let file = dir.join("secret.json");

        write_secret(&file, b"{\"key\":\"secret\"}").expect("write_secret must succeed");
        assert_eq!(std::fs::read(&file).unwrap(), b"{\"key\":\"secret\"}");

        let wide: Vec<u16> = file.as_os_str().encode_wide().chain(Some(0)).collect();
        let sd = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let err = unsafe {
            GetNamedSecurityInfoW(
                windows::core::PCWSTR::from_raw(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                sd,
            )
        };
        assert_eq!(err, NO_ERROR, "GetNamedSecurityInfoW must succeed");

        assert!(!dacl.is_null(), "DACL must not be NULL after write_secret");

        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(sd as *mut _)));
        }

        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file)
            .expect("owner retains write access after write_secret");
        assert_eq!(std::fs::read(&file).unwrap(), b"");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn data_dir_honors_cf_scanner_data_dir_override() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let isolated = IsolatedDataDir::new();
        let dir = isolated.path();
        assert_eq!(data_dir().unwrap(), dir);
        assert_eq!(refreshed_ranges_path().unwrap(), dir.join("cf-ranges.txt"));
        assert_eq!(
            refreshed_ranges_v6_path().unwrap(),
            dir.join("cf-ranges-v6.txt")
        );
        assert_eq!(xray_binary_path().unwrap().parent().unwrap(), dir);
    }

    #[test]
    fn xray_binary_path_uses_platform_exe_name() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        let expected = if cfg!(windows) { "xray.exe" } else { "xray" };
        assert_eq!(
            xray_binary_path()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn default_data_dir_is_absolute() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        assert!(data_dir().unwrap().is_absolute());
    }
}
