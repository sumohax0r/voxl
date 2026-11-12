//! OS password verification. Authentication never changes the process identity or desktop.
#[cfg(unix)]
pub fn verify(user: &str, password: &str, service: &str) -> bool {
    use libc::{c_char, c_int, c_void};
    use std::ffi::CString;
    #[repr(C)]
    struct Message {
        style: c_int,
        text: *const c_char,
    }
    #[repr(C)]
    struct Response {
        text: *mut c_char,
        code: c_int,
    }
    #[repr(C)]
    struct Conversation {
        callback: unsafe extern "C" fn(
            c_int,
            *const *const Message,
            *mut *mut Response,
            *mut c_void,
        ) -> c_int,
        data: *mut c_void,
    }
    #[link(name = "pam")]
    unsafe extern "C" {
        fn pam_start(
            service: *const c_char,
            user: *const c_char,
            conv: *const Conversation,
            handle: *mut *mut c_void,
        ) -> c_int;
        fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
        fn pam_acct_mgmt(handle: *mut c_void, flags: c_int) -> c_int;
        fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    }
    struct Credentials {
        user: CString,
        password: CString,
    }
    unsafe extern "C" fn converse(
        n: c_int,
        messages: *const *const Message,
        result: *mut *mut Response,
        data: *mut c_void,
    ) -> c_int {
        // PAM owns the returned calloc/strdup allocations and frees them.
        unsafe {
            if n <= 0 || n > 32 || messages.is_null() || result.is_null() {
                return 19;
            }
            let creds = &*(data as *const Credentials);
            let replies =
                libc::calloc(n as usize, std::mem::size_of::<Response>()) as *mut Response;
            if replies.is_null() {
                return 19;
            }
            for i in 0..n as usize {
                let message = *messages.add(i);
                let source = if message.is_null() {
                    None
                } else {
                    match (*message).style {
                        1 => Some(creds.password.as_ptr()),
                        2 => Some(creds.user.as_ptr()),
                        3 | 4 => Some(std::ptr::null()),
                        _ => None,
                    }
                };
                if let Some(source) = source {
                    if source.is_null() {
                        continue;
                    }
                    (*replies.add(i)).text = libc::strdup(source);
                    if !(*replies.add(i)).text.is_null() {
                        continue;
                    }
                }
                for j in 0..=i {
                    libc::free((*replies.add(j)).text.cast());
                }
                libc::free(replies.cast());
                return 19;
            }
            *result = replies;
            0
        }
    }
    let (Ok(user), Ok(password), Ok(service)) = (
        CString::new(user),
        CString::new(password),
        CString::new(service),
    ) else {
        return false;
    };
    let mut creds = Credentials { user, password };
    let conv = Conversation {
        callback: converse,
        data: (&mut creds as *mut Credentials).cast(),
    };
    let mut handle = std::ptr::null_mut();
    unsafe {
        let start = pam_start(service.as_ptr(), creds.user.as_ptr(), &conv, &mut handle);
        if start != 0 {
            return false;
        }
        // Disallow null authentication tokens, then check expired/disabled accounts.
        let mut status = pam_authenticate(handle, 1);
        if status == 0 {
            status = pam_acct_mgmt(handle, 0);
        }
        pam_end(handle, status);
        status == 0
    }
}

#[cfg(windows)]
pub fn verify(user: &str, password: &str, _service: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT};
    if user.contains('\0') || password.contains('\0') {
        return false;
    }
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    // Unqualified names are local. Explicit DOMAIN\\user and UPNs also work when allowed.
    let (domain, name) = user
        .split_once('\\')
        .unwrap_or((if user.contains('@') { "" } else { "." }, user));
    let name = wide(name);
    let domain = wide(domain);
    let mut password = wide(password);
    let mut token = HANDLE::default();
    let ok = unsafe {
        LogonUserW(
            PCWSTR(name.as_ptr()),
            if domain.len() == 1 {
                PCWSTR::null()
            } else {
                PCWSTR(domain.as_ptr())
            },
            PCWSTR(password.as_ptr()),
            LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    }
    .is_ok();
    for c in &mut password {
        unsafe {
            std::ptr::write_volatile(c, 0);
        }
    }
    if ok {
        let _ = unsafe { CloseHandle(token) };
    }
    ok
}

#[cfg(test)]
mod tests {
    /// Opt-in native verification against a disposable test account. CI creates and
    /// deletes that account; no real user's password is embedded in the test binary.
    #[test]
    #[ignore = "requires a disposable OS account supplied through environment variables"]
    fn native_account() {
        let user = std::env::var("VOXL_TEST_OS_USER").expect("test account name");
        let password = std::env::var("VOXL_TEST_OS_PASSWORD").expect("test account password");
        let service = std::env::var("VOXL_TEST_PAM_SERVICE").unwrap_or_else(|_| "voxl".into());
        if std::env::var_os("VOXL_TEST_ACCOUNT_DISABLED").is_some() {
            assert!(
                !super::verify(&user, &password, &service),
                "disabled account admitted"
            );
        } else {
            assert!(
                super::verify(&user, &password, &service),
                "valid account rejected"
            );
            assert!(
                !super::verify(&user, &format!("{password}-incorrect"), &service),
                "wrong password admitted"
            );
        }
    }
}
