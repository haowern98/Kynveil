use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

const PROFILE_DIRECTORY: &str = "core";
const MEDIA_DIRECTORY: &str = "media";
const METADATA_FILE: &str = "profile.meta";
const DATABASE_FILE: &str = "profile.db";
const USER_DATA_ROOT_ARGUMENT_PREFIX: &str = "--user-data-root=";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProfilePaths {
    pub(crate) root: PathBuf,
    pub(crate) metadata: PathBuf,
    pub(crate) database: PathBuf,
    pub(crate) database_wal: PathBuf,
    pub(crate) database_shm: PathBuf,
    pub(crate) media: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProfilePathError {
    RootIsNotAbsolute,
    RootIsNotDirectory,
    InvalidBootstrapArguments,
    UnexpectedPathType,
    #[cfg(unix)]
    UnsafePermissions,
    Io,
    WindowsSecurity,
}

impl ProfilePaths {
    pub(crate) fn validate_process_arguments() -> Result<(), ProfilePathError> {
        Self::from_sidecar_arguments(std::env::args_os().skip(1)).map(|_| ())
    }

    pub(crate) fn from_sidecar_arguments(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Option<Self>, ProfilePathError> {
        let mut root = None;
        for argument in arguments {
            let Some(argument) = argument.to_str() else {
                return Err(ProfilePathError::InvalidBootstrapArguments);
            };
            let Some(value) = argument.strip_prefix(USER_DATA_ROOT_ARGUMENT_PREFIX) else {
                return Err(ProfilePathError::InvalidBootstrapArguments);
            };
            if root.replace(PathBuf::from(value)).is_some() {
                return Err(ProfilePathError::InvalidBootstrapArguments);
            }
        }
        root.as_deref().map(Self::from_user_data_root).transpose()
    }

    pub(crate) fn from_user_data_root(user_data_root: &Path) -> Result<Self, ProfilePathError> {
        if !user_data_root.is_absolute() {
            return Err(ProfilePathError::RootIsNotAbsolute);
        }
        if !fs::metadata(user_data_root)
            .map_err(|_| ProfilePathError::Io)?
            .is_dir()
        {
            return Err(ProfilePathError::RootIsNotDirectory);
        }

        let root = user_data_root.join(PROFILE_DIRECTORY);
        ensure_profile_directory(&root)?;

        let media = root.join(MEDIA_DIRECTORY);
        ensure_profile_directory(&media)?;

        let database = root.join(DATABASE_FILE);
        let paths = Self {
            metadata: root.join(METADATA_FILE),
            database_wal: root.join(format!("{DATABASE_FILE}-wal")),
            database_shm: root.join(format!("{DATABASE_FILE}-shm")),
            root,
            database,
            media,
        };
        paths.validate_existing_state_files()?;
        Ok(paths)
    }

    fn validate_existing_state_files(&self) -> Result<(), ProfilePathError> {
        for path in [
            &self.metadata,
            &self.database,
            &self.database_wal,
            &self.database_shm,
        ] {
            validate_existing_state_file(path)?;
        }
        Ok(())
    }

    pub(crate) fn protect_state_files(&self) -> Result<(), ProfilePathError> {
        self.validate_existing_state_files()
    }

    /// Removes only the fixed Stage 3 profile artefacts after their connection is closed.
    ///
    /// Unknown content and media cause failure rather than widening deletion beyond the
    /// storage layout that this version owns.
    pub(crate) fn delete_profile_artifacts(&self) -> Result<(), ProfilePathError> {
        self.validate_existing_state_files()?;
        validate_profile_directory(&self.root)?;
        validate_profile_directory(&self.media)?;
        if fs::read_dir(&self.media)
            .map_err(|_| ProfilePathError::Io)?
            .next()
            .is_some()
        {
            return Err(ProfilePathError::UnexpectedPathType);
        }
        for entry in fs::read_dir(&self.root).map_err(|_| ProfilePathError::Io)? {
            let name = entry.map_err(|_| ProfilePathError::Io)?.file_name();
            if ![
                OsString::from(METADATA_FILE),
                OsString::from(DATABASE_FILE),
                OsString::from(format!("{DATABASE_FILE}-wal")),
                OsString::from(format!("{DATABASE_FILE}-shm")),
                OsString::from(MEDIA_DIRECTORY),
            ]
            .contains(&name)
            {
                return Err(ProfilePathError::UnexpectedPathType);
            }
        }
        fs::remove_dir(&self.media).map_err(|_| ProfilePathError::Io)?;
        for path in [
            &self.metadata,
            &self.database,
            &self.database_wal,
            &self.database_shm,
        ] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(ProfilePathError::Io),
            }
        }
        fs::remove_dir(&self.root).map_err(|_| ProfilePathError::Io)
    }
}

fn ensure_profile_directory(path: &Path) -> Result<(), ProfilePathError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ProfilePathError::UnexpectedPathType);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| ProfilePathError::Io)?;
        }
        Err(_) => return Err(ProfilePathError::Io),
    }

    validate_profile_directory(path)
}

fn validate_profile_directory(path: &Path) -> Result<(), ProfilePathError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProfilePathError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProfilePathError::UnexpectedPathType);
    }

    #[cfg(unix)]
    unix_profile_security::protect_directory(path, &metadata)?;
    #[cfg(windows)]
    windows_profile_security::protect_directory(path)?;
    Ok(())
}

fn validate_existing_state_file(path: &Path) -> Result<(), ProfilePathError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ProfilePathError::Io),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProfilePathError::UnexpectedPathType);
    }

    #[cfg(unix)]
    unix_profile_security::protect_file(path, &metadata)?;
    #[cfg(windows)]
    windows_profile_security::protect_file(path)?;
    Ok(())
}

#[cfg(unix)]
mod unix_profile_security {
    use std::{
        fs::{self, Metadata},
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::Path,
    };

    use super::ProfilePathError;

    pub(super) fn protect_directory(
        path: &Path,
        metadata: &Metadata,
    ) -> Result<(), ProfilePathError> {
        protect_owned_path(path, metadata, 0o700)
    }

    pub(super) fn protect_file(path: &Path, metadata: &Metadata) -> Result<(), ProfilePathError> {
        protect_owned_path(path, metadata, 0o600)
    }

    fn protect_owned_path(
        path: &Path,
        metadata: &Metadata,
        required_mode: u32,
    ) -> Result<(), ProfilePathError> {
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(ProfilePathError::UnsafePermissions);
        }
        if metadata.mode() & 0o077 != 0 || metadata.permissions().mode() != required_mode {
            fs::set_permissions(path, fs::Permissions::from_mode(required_mode))
                .map_err(|_| ProfilePathError::Io)?;
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows_profile_security {
    use std::{
        ffi::c_void,
        os::windows::ffi::OsStrExt,
        path::Path,
        ptr::{self, NonNull},
    };

    use windows::{
        Win32::{
            Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
            Security::Authorization::{
                BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetExplicitEntriesFromAclW,
                GetSecurityInfo, SE_FILE_OBJECT, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID,
                TRUSTEE_W,
            },
            Security::{
                CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
                GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetTokenInformation,
                PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
                SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser,
                WinBuiltinAdministratorsSid, WinLocalSystemSid,
            },
            Storage::FileSystem::{
                CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
                FileAttributeTagInfo, GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL,
                WRITE_DAC,
            },
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        },
        core::{BOOL, HRESULT, PCWSTR},
    };

    use super::ProfilePathError;

    #[derive(Debug)]
    pub(super) struct DaclInspection {
        pub(super) is_protected: bool,
        pub(super) explicit_ace_count: u32,
        principals: u8,
        is_restrictive: bool,
    }

    impl DaclInspection {
        const CURRENT_USER: u8 = 1;
        const SYSTEM: u8 = 1 << 1;
        const ADMINISTRATORS: u8 = 1 << 2;

        pub(super) fn has_current_user(&self) -> bool {
            self.principals & Self::CURRENT_USER != 0
        }

        pub(super) fn has_system(&self) -> bool {
            self.principals & Self::SYSTEM != 0
        }

        pub(super) fn has_administrators(&self) -> bool {
            self.principals & Self::ADMINISTRATORS != 0
        }
    }

    pub(super) fn protect_directory(path: &Path) -> Result<(), ProfilePathError> {
        protect_path(path, true)
    }

    pub(super) fn protect_file(path: &Path) -> Result<(), ProfilePathError> {
        protect_path(path, false)
    }

    fn protect_path(path: &Path, is_directory: bool) -> Result<(), ProfilePathError> {
        let path = open_profile_path(path)?;
        if path.is_directory() != is_directory {
            return Err(ProfilePathError::WindowsSecurity);
        }
        let principals = ProfilePrincipals::current()?;
        let inheritance = if is_directory {
            windows::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            windows::Win32::Security::NO_INHERITANCE
        };
        let mut trustees = [TRUSTEE_W::default(); 3];
        build_trustee(&mut trustees[0], principals.current_user_sid()?)?;
        build_trustee(&mut trustees[1], principals.system_sid())?;
        build_trustee(&mut trustees[2], principals.administrators_sid())?;
        let entries = trustees.map(|trustee| EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee,
        });
        let acl = new_acl(&entries)?;

        set_handle_dacl(&path.handle, acl.as_ptr())?;
        let inspection = inspect_profile_dacl_with_principals(&path, &principals)?;
        if !inspection.is_restrictive {
            return Err(ProfilePathError::WindowsSecurity);
        }
        Ok(())
    }

    pub(super) fn inspect_profile_dacl(path: &Path) -> Result<DaclInspection, ProfilePathError> {
        let path = open_profile_path(path)?;
        let principals = ProfilePrincipals::current()?;
        inspect_profile_dacl_with_principals(&path, &principals)
    }

    #[cfg(test)]
    pub(super) fn set_null_dacl_for_test(path: &Path) -> Result<(), ProfilePathError> {
        let path = open_profile_path(path)?;
        set_null_dacl(&path.handle)
    }

    #[cfg(test)]
    pub(super) fn verify_final_component_for_test(path: &Path) -> Result<(), ProfilePathError> {
        open_profile_path(path).map(|_| ())
    }

    fn inspect_profile_dacl_with_principals(
        path: &OpenedProfilePath,
        principals: &ProfilePrincipals,
    ) -> Result<DaclInspection, ProfilePathError> {
        let descriptor = security_descriptor(&path.handle)?;
        let dacl = descriptor.dacl()?;
        let is_protected = descriptor.is_dacl_protected()?;
        let entries = explicit_entries(dacl)?;
        let entries = entries.as_slice();
        let expected_inheritance = if path.is_directory() {
            windows::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            windows::Win32::Security::NO_INHERITANCE
        };

        let mut principals_seen = 0_u8;
        let mut is_restrictive = is_protected && entries.len() == 3;
        for entry in entries {
            if entry.grfAccessMode != GRANT_ACCESS
                || entry.grfAccessPermissions != FILE_ALL_ACCESS.0
                || entry.grfInheritance != expected_inheritance
                || entry.Trustee.TrusteeForm != TRUSTEE_IS_SID
                || entry.Trustee.ptstrName.0.is_null()
            {
                is_restrictive = false;
                continue;
            }

            let sid = PSID(entry.Trustee.ptstrName.0.cast());
            if equal_sid(sid, principals.current_user_sid()?)? {
                if principals_seen & DaclInspection::CURRENT_USER != 0 {
                    is_restrictive = false;
                }
                principals_seen |= DaclInspection::CURRENT_USER;
            } else if equal_sid(sid, principals.system_sid())? {
                if principals_seen & DaclInspection::SYSTEM != 0 {
                    is_restrictive = false;
                }
                principals_seen |= DaclInspection::SYSTEM;
            } else if equal_sid(sid, principals.administrators_sid())? {
                if principals_seen & DaclInspection::ADMINISTRATORS != 0 {
                    is_restrictive = false;
                }
                principals_seen |= DaclInspection::ADMINISTRATORS;
            } else {
                is_restrictive = false;
            }
        }
        is_restrictive &= principals_seen
            == DaclInspection::CURRENT_USER
                | DaclInspection::SYSTEM
                | DaclInspection::ADMINISTRATORS;

        Ok(DaclInspection {
            is_protected,
            explicit_ace_count: u32::try_from(entries.len())
                .map_err(|_| ProfilePathError::WindowsSecurity)?,
            principals: principals_seen,
            is_restrictive,
        })
    }

    struct ProfilePrincipals {
        token_user: Vec<usize>,
        system: Box<[u8; SECURITY_MAX_SID_SIZE as usize]>,
        administrators: Box<[u8; SECURITY_MAX_SID_SIZE as usize]>,
    }

    impl ProfilePrincipals {
        fn current() -> Result<Self, ProfilePathError> {
            let token_user = current_user_sid_buffer()?;
            let system = well_known_sid(WinLocalSystemSid)?;
            let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
            Ok(Self {
                token_user,
                system,
                administrators,
            })
        }

        fn current_user_sid(&self) -> Result<PSID, ProfilePathError> {
            sid_from_token_buffer(&self.token_user)
        }

        fn system_sid(&self) -> PSID {
            PSID(self.system.as_ptr().cast_mut().cast())
        }

        fn administrators_sid(&self) -> PSID {
            PSID(self.administrators.as_ptr().cast_mut().cast())
        }
    }

    struct OwnedHandle(HANDLE);

    struct OpenedProfilePath {
        handle: OwnedHandle,
        attributes: u32,
    }

    impl OpenedProfilePath {
        fn is_directory(&self) -> bool {
            self.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        }
    }

    impl Drop for OwnedHandle {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: this is an owned, non-pseudo handle returned by either
            // OpenProcessToken or CreateFileW; CloseHandle is its matching release API.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    struct LocalAllocation(NonNull<c_void>);

    impl Drop for LocalAllocation {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: each constructor accepts only allocations returned by APIs that
            // document LocalFree as their matching release operation; this wrapper owns
            // the allocation exactly once and no references escape its lifetime.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.as_ptr()))) };
        }
    }

    struct OwnedAcl(LocalAllocation);

    impl OwnedAcl {
        fn as_ptr(&self) -> *const windows::Win32::Security::ACL {
            self.0.0.as_ptr().cast()
        }
    }

    struct SecurityDescriptor(LocalAllocation);

    impl SecurityDescriptor {
        fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
            PSECURITY_DESCRIPTOR(self.0.0.as_ptr())
        }

        fn dacl(&self) -> Result<*mut windows::Win32::Security::ACL, ProfilePathError> {
            let mut present = BOOL(0);
            let mut dacl = ptr::null_mut();
            let mut defaulted = BOOL(0);
            get_security_descriptor_dacl(self.as_ptr(), &mut present, &mut dacl, &mut defaulted)?;
            if !present.as_bool() || dacl.is_null() {
                return Err(ProfilePathError::WindowsSecurity);
            }
            Ok(dacl)
        }

        fn is_dacl_protected(&self) -> Result<bool, ProfilePathError> {
            let mut control = 0_u16;
            let mut revision = 0_u32;
            get_security_descriptor_control(self.as_ptr(), &mut control, &mut revision)?;
            Ok((control & SE_DACL_PROTECTED.0) != 0)
        }
    }

    struct ExplicitEntries {
        _allocation: LocalAllocation,
        entries: NonNull<EXPLICIT_ACCESS_W>,
        count: usize,
    }

    impl ExplicitEntries {
        #[allow(unsafe_code)]
        fn as_slice(&self) -> &[EXPLICIT_ACCESS_W] {
            // SAFETY: GetExplicitEntriesFromAclW initialized exactly count entries at this
            // pointer, and allocation retains the LocalAlloc buffer for the returned slice.
            unsafe { std::slice::from_raw_parts(self.entries.as_ptr(), self.count) }
        }
    }

    fn to_wide_path(path: &Path) -> Result<Vec<u16>, ProfilePathError> {
        let mut path_wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if path_wide.contains(&0) {
            return Err(ProfilePathError::WindowsSecurity);
        }
        path_wide.push(0);
        Ok(path_wide)
    }

    #[allow(unsafe_code)]
    fn open_profile_path(path: &Path) -> Result<OpenedProfilePath, ProfilePathError> {
        let path_wide = to_wide_path(path)?;
        // SAFETY: path_wide is NUL-terminated without interior NUL and remains live for
        // this synchronous call. The resulting owned handle is checked and closed by
        // OwnedHandle. OPEN_REPARSE_POINT opens the final path component itself, so a
        // junction or symlink cannot redirect the following security operations. Parent
        // traversal remains anchored in Electron's trusted userData bootstrap root; this
        // does not claim to defend against the same unlocked OS user replacing ancestors.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                READ_CONTROL.0 | WRITE_DAC.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|_| ProfilePathError::WindowsSecurity)?;
        if handle.0.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        let handle = OwnedHandle(handle);
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let attribute_size = u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>())
            .map_err(|_| ProfilePathError::WindowsSecurity)?;
        // SAFETY: handle is a live CreateFileW handle, attributes is writable for exactly
        // attribute_size bytes, and the API writes synchronously without retaining either.
        unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileAttributeTagInfo,
                (&raw mut attributes).cast(),
                attribute_size,
            )
        }
        .map_err(|_| ProfilePathError::WindowsSecurity)?;
        if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(ProfilePathError::WindowsSecurity);
        }
        Ok(OpenedProfilePath {
            handle,
            attributes: attributes.FileAttributes,
        })
    }

    #[allow(unsafe_code)]
    fn current_user_sid_buffer() -> Result<Vec<usize>, ProfilePathError> {
        let mut token = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle for this process;
        // token points to writable HANDLE storage and OwnedHandle closes it exactly once.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
            .map_err(|_| ProfilePathError::WindowsSecurity)?;
        if token.0.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        let token = OwnedHandle(token);
        let mut required = 0_u32;
        // SAFETY: this documented sizing call deliberately supplies no buffer and a live
        // return-length pointer; the result is checked and no returned pointer is used.
        let initial =
            unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut required) };
        let Err(error) = initial else {
            return Err(ProfilePathError::WindowsSecurity);
        };
        if error.code()
            != HRESULT::from_win32(windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER.0)
            || required == 0
        {
            return Err(ProfilePathError::WindowsSecurity);
        }
        let bytes = usize::try_from(required).map_err(|_| ProfilePathError::WindowsSecurity)?;
        let word_size = std::mem::size_of::<usize>();
        let words = bytes
            .checked_add(word_size - 1)
            .and_then(|value| value.checked_div(word_size))
            .ok_or(ProfilePathError::WindowsSecurity)?;
        let mut buffer = vec![0_usize; words];
        // SAFETY: buffer is aligned for TOKEN_USER, is at least required bytes long, and
        // remains owned for the call; the API writes only within the supplied length.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                required,
                &raw mut required,
            )
        }
        .map_err(|_| ProfilePathError::WindowsSecurity)?;
        Ok(buffer)
    }

    #[allow(unsafe_code)]
    fn sid_from_token_buffer(buffer: &[usize]) -> Result<PSID, ProfilePathError> {
        if std::mem::size_of_val(buffer) < std::mem::size_of::<TOKEN_USER>() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        // SAFETY: current_user_sid_buffer allocated aligned storage and populated it via
        // GetTokenInformation(TokenUser); the TOKEN_USER header fits in this buffer.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        if user.User.Sid.0.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        Ok(user.User.Sid)
    }

    #[allow(unsafe_code)]
    fn well_known_sid(
        kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE,
    ) -> Result<Box<[u8; SECURITY_MAX_SID_SIZE as usize]>, ProfilePathError> {
        let mut bytes = Box::new([0_u8; SECURITY_MAX_SID_SIZE as usize]);
        let mut length = SECURITY_MAX_SID_SIZE;
        let sid = PSID(bytes.as_mut_ptr().cast());
        // SAFETY: bytes is writable for SECURITY_MAX_SID_SIZE bytes, length points to its
        // exact capacity, and CreateWellKnownSid writes synchronously without retaining it.
        unsafe { CreateWellKnownSid(kind, None, Some(sid), &raw mut length) }
            .map_err(|_| ProfilePathError::WindowsSecurity)?;
        if length == 0 || length > SECURITY_MAX_SID_SIZE {
            return Err(ProfilePathError::WindowsSecurity);
        }
        Ok(bytes)
    }

    #[allow(unsafe_code)]
    fn build_trustee(trustee: &mut TRUSTEE_W, sid: PSID) -> Result<(), ProfilePathError> {
        if sid.0.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        // SAFETY: trustee is writable for TRUSTEE_W and sid references principal storage
        // retained by ProfilePrincipals for the whole ACL construction call sequence.
        unsafe { BuildTrusteeWithSidW(trustee, Some(sid)) };
        if trustee.TrusteeForm != TRUSTEE_IS_SID || trustee.ptstrName.0.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn new_acl(entries: &[EXPLICIT_ACCESS_W; 3]) -> Result<OwnedAcl, ProfilePathError> {
        let mut acl = ptr::null_mut();
        // SAFETY: entries is a live three-element array of initialized EXPLICIT_ACCESS_W
        // values whose trustee SID pointers remain valid throughout this synchronous call;
        // acl is writable output storage and the returned allocation is wrapped in LocalFree.
        let result = unsafe { SetEntriesInAclW(Some(entries), None, &raw mut acl) };
        if !result.is_ok() || acl.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        let allocation = NonNull::new(acl.cast()).ok_or(ProfilePathError::WindowsSecurity)?;
        Ok(OwnedAcl(LocalAllocation(allocation)))
    }

    #[allow(unsafe_code)]
    fn set_handle_dacl(
        handle: &OwnedHandle,
        dacl: *const windows::Win32::Security::ACL,
    ) -> Result<(), ProfilePathError> {
        if handle.0.0.is_null() || dacl.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        // SAFETY: handle identifies the exact checked profile object and stays open for
        // the call. dacl is a LocalAlloc allocation held by OwnedAcl; neither is retained.
        let result = unsafe {
            SetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        };
        if !result.is_ok() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        Ok(())
    }

    #[cfg(test)]
    #[allow(unsafe_code)]
    fn set_null_dacl(handle: &OwnedHandle) -> Result<(), ProfilePathError> {
        if handle.0.0.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        // SAFETY: handle identifies the exact checked profile object and stays open for
        // the call. A null DACL deliberately creates the insecure condition that the
        // production inspection must reject.
        let result = unsafe {
            SetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
            )
        };
        if !result.is_ok() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn security_descriptor(handle: &OwnedHandle) -> Result<SecurityDescriptor, ProfilePathError> {
        if handle.0.0.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        let mut descriptor = PSECURITY_DESCRIPTOR(ptr::null_mut());
        // SAFETY: handle identifies the exact checked profile object and stays open for
        // this call. descriptor is writable output storage; its LocalAlloc result is owned
        // immediately below and released exactly once by SecurityDescriptor.
        let result = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                Some(&raw mut descriptor),
            )
        };
        if !result.is_ok() || descriptor.0.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        let allocation = NonNull::new(descriptor.0).ok_or(ProfilePathError::WindowsSecurity)?;
        Ok(SecurityDescriptor(LocalAllocation(allocation)))
    }

    #[allow(unsafe_code)]
    fn get_security_descriptor_dacl(
        descriptor: PSECURITY_DESCRIPTOR,
        present: &mut BOOL,
        dacl: &mut *mut windows::Win32::Security::ACL,
        defaulted: &mut BOOL,
    ) -> Result<(), ProfilePathError> {
        // SAFETY: descriptor is a live GetSecurityInfo allocation; all output
        // references point to writable local storage for this synchronous inspection call.
        unsafe { GetSecurityDescriptorDacl(descriptor, present, dacl, defaulted) }
            .map_err(|_| ProfilePathError::WindowsSecurity)
    }

    #[allow(unsafe_code)]
    fn get_security_descriptor_control(
        descriptor: PSECURITY_DESCRIPTOR,
        control: &mut u16,
        revision: &mut u32,
    ) -> Result<(), ProfilePathError> {
        // SAFETY: descriptor is a live GetSecurityInfo allocation and control and
        // revision are writable local output storage for this synchronous inspection call.
        unsafe { GetSecurityDescriptorControl(descriptor, control, revision) }
            .map_err(|_| ProfilePathError::WindowsSecurity)
    }

    #[allow(unsafe_code)]
    fn explicit_entries(
        dacl: *mut windows::Win32::Security::ACL,
    ) -> Result<ExplicitEntries, ProfilePathError> {
        if dacl.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        let mut count = 0_u32;
        let mut entries = ptr::null_mut();
        // SAFETY: dacl points into the live security descriptor; count and entries are
        // writable outputs; returned LocalAlloc memory is immediately owned by LocalAllocation.
        let result = unsafe { GetExplicitEntriesFromAclW(dacl, &raw mut count, &raw mut entries) };
        if !result.is_ok() || entries.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        let count = usize::try_from(count).map_err(|_| ProfilePathError::WindowsSecurity)?;
        let entries = NonNull::new(entries).ok_or(ProfilePathError::WindowsSecurity)?;
        let allocation = LocalAllocation(
            NonNull::new(entries.as_ptr().cast()).ok_or(ProfilePathError::WindowsSecurity)?,
        );
        Ok(ExplicitEntries {
            _allocation: allocation,
            entries,
            count,
        })
    }

    #[allow(unsafe_code)]
    fn equal_sid(left: PSID, right: PSID) -> Result<bool, ProfilePathError> {
        if left.0.is_null() || right.0.is_null() {
            return Err(ProfilePathError::WindowsSecurity);
        }
        // SAFETY: both SIDs are non-null pointers supplied by Windows principal/ACL APIs
        // and remain live for this synchronous equality check; EqualSid retains neither.
        Ok(unsafe { EqualSid(left, right) }.is_ok())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
    };

    use super::{ProfilePathError, ProfilePaths};

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let mut nonce = [0_u8; 8];
            getrandom::fill(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "kynveil-profile-path-test-{}-{}",
                std::process::id(),
                u64::from_be_bytes(nonce)
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn rejects_a_relative_user_data_root() {
        assert_eq!(
            ProfilePaths::from_user_data_root(Path::new("relative")),
            Err(ProfilePathError::RootIsNotAbsolute)
        );
    }

    #[test]
    fn parses_only_one_absolute_user_data_root_bootstrap_argument() {
        let directory = TestDirectory::new();
        let argument = OsString::from(format!("--user-data-root={}", directory.path.display()));

        let paths = ProfilePaths::from_sidecar_arguments([argument])
            .unwrap()
            .unwrap();

        assert_eq!(paths.root, directory.path.join("core"));
    }

    #[test]
    fn rejects_unknown_duplicate_and_relative_bootstrap_arguments() {
        let directory = TestDirectory::new();
        assert_eq!(
            ProfilePaths::from_sidecar_arguments([OsString::from("--unknown=value")]),
            Err(ProfilePathError::InvalidBootstrapArguments)
        );
        assert_eq!(
            ProfilePaths::from_sidecar_arguments([
                OsString::from(format!("--user-data-root={}", directory.path.display())),
                OsString::from(format!("--user-data-root={}", directory.path.display())),
            ]),
            Err(ProfilePathError::InvalidBootstrapArguments)
        );
        assert_eq!(
            ProfilePaths::from_sidecar_arguments([OsString::from("--user-data-root=relative")]),
            Err(ProfilePathError::RootIsNotAbsolute)
        );
    }

    #[test]
    fn creates_only_the_fixed_kynveil_children() {
        let directory = TestDirectory::new();
        let paths = ProfilePaths::from_user_data_root(&directory.path).unwrap();

        assert_eq!(paths.root, directory.path.join("core"));
        assert_eq!(paths.metadata, paths.root.join("profile.meta"));
        assert_eq!(paths.database, paths.root.join("profile.db"));
        assert_eq!(paths.database_wal, paths.root.join("profile.db-wal"));
        assert_eq!(paths.database_shm, paths.root.join("profile.db-shm"));
        assert_eq!(paths.media, paths.root.join("media"));
        assert!(paths.root.is_dir());
        assert!(paths.media.is_dir());
    }

    #[test]
    fn rejects_an_existing_non_directory_profile_root() {
        let directory = TestDirectory::new();
        fs::write(directory.path.join("core"), b"not a directory").unwrap();

        assert_eq!(
            ProfilePaths::from_user_data_root(&directory.path),
            Err(ProfilePathError::UnexpectedPathType)
        );
    }

    #[test]
    fn safely_reopens_the_same_fixed_profile_paths() {
        let directory = TestDirectory::new();
        let first = ProfilePaths::from_user_data_root(&directory.path).unwrap();
        let second = ProfilePaths::from_user_data_root(&directory.path).unwrap();

        assert_eq!(first, second);
    }

    #[cfg(unix)]
    #[test]
    fn enforces_private_unix_modes_on_profile_directories_and_state_files() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = TestDirectory::new();
        let paths = ProfilePaths::from_user_data_root(&directory.path).unwrap();
        assert_eq!(
            fs::metadata(&paths.root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&paths.media).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&paths.root).unwrap().uid(),
            rustix::process::geteuid().as_raw()
        );

        fs::write(&paths.metadata, b"non-secret test metadata").unwrap();
        fs::set_permissions(&paths.metadata, fs::Permissions::from_mode(0o644)).unwrap();
        ProfilePaths::from_user_data_root(&directory.path).unwrap();

        assert_eq!(
            fs::metadata(&paths.metadata).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_an_existing_symlinked_profile_root() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let target = directory.path.join("target");
        fs::create_dir(&target).unwrap();
        symlink(&target, directory.path.join("core")).unwrap();

        assert_eq!(
            ProfilePaths::from_user_data_root(&directory.path),
            Err(ProfilePathError::UnexpectedPathType)
        );
    }

    #[cfg(windows)]
    #[test]
    fn rejects_an_existing_symlinked_profile_root() {
        use std::process::Command;

        let directory = TestDirectory::new();
        let target = directory.path.join("target");
        let link = directory.path.join("core");
        fs::create_dir(&target).unwrap();
        let link_literal = link.display().to_string().replace('\'', "''");
        let target_literal = target.display().to_string().replace('\'', "''");
        let command = format!(
            "New-Item -ItemType Junction -Path '{link_literal}' -Target '{target_literal}' | Out-Null"
        );
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &command])
            .status()
            .unwrap();
        assert!(status.success(), "{command}");

        assert!(matches!(
            super::windows_profile_security::verify_final_component_for_test(&link),
            Err(ProfilePathError::WindowsSecurity)
        ));

        assert_eq!(
            ProfilePaths::from_user_data_root(&directory.path),
            Err(ProfilePathError::UnexpectedPathType)
        );
        fs::remove_dir(link).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn applies_and_inspects_the_restrictive_windows_profile_dacl() {
        let directory = TestDirectory::new();
        let paths = ProfilePaths::from_user_data_root(&directory.path).unwrap();
        let inspection =
            super::windows_profile_security::inspect_profile_dacl(&paths.root).unwrap();

        assert!(inspection.is_protected);
        assert_eq!(inspection.explicit_ace_count, 3);
        assert!(inspection.has_current_user());
        assert!(inspection.has_system());
        assert!(inspection.has_administrators());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_a_null_windows_dacl() {
        let directory = TestDirectory::new();
        let profile_root = directory.path.join("core");
        fs::create_dir(&profile_root).unwrap();
        super::windows_profile_security::set_null_dacl_for_test(&profile_root).unwrap();

        assert!(matches!(
            super::windows_profile_security::inspect_profile_dacl(&profile_root),
            Err(ProfilePathError::WindowsSecurity)
        ));
    }
}
