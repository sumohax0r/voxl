//! Optional native Winlogon bridge. Load only from the administrator-installed path;
//! never search the working directory or PATH for a credential-provider DLL.
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

type SignIn = unsafe extern "system" fn(*const u16, *const u16) -> u32;
type Busy = unsafe extern "system" fn() -> u32;
struct Bridge {
    sign_in: SignIn,
    busy: Busy,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(
        path: *const u16,
        file: *mut std::ffi::c_void,
        flags: u32,
    ) -> *mut std::ffi::c_void;
    fn GetProcAddress(module: *mut std::ffi::c_void, name: *const u8) -> *mut std::ffi::c_void;
}
fn bridge() -> Option<&'static Bridge> {
    static BRIDGE: OnceLock<Option<Bridge>> = OnceLock::new();
    BRIDGE
        .get_or_init(|| {
            let root =
                std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles"))?;
            use std::os::windows::ffi::OsStrExt;
            let path = std::path::PathBuf::from(root)
                .join("VoxlLogon")
                .join("voxl-logon.dll");
            let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            unsafe {
                // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
                let module = LoadLibraryExW(path.as_ptr(), std::ptr::null_mut(), 0x100 | 0x800);
                if module.is_null() {
                    return None;
                }
                let sign_in = GetProcAddress(module, c"VoxlSignIn".as_ptr().cast());
                let busy = GetProcAddress(module, c"VoxlRdpBusy".as_ptr().cast());
                if sign_in.is_null() || busy.is_null() {
                    return None;
                }
                // The module remains loaded for the process lifetime.
                Some(Bridge {
                    sign_in: std::mem::transmute::<*mut std::ffi::c_void, SignIn>(sign_in),
                    busy: std::mem::transmute::<*mut std::ffi::c_void, Busy>(busy),
                })
            }
        })
        .as_ref()
}
pub fn sign_in(user: &str, password: &str) -> u32 {
    let Some(bridge) = bridge() else {
        return 4;
    };
    if user.contains('\0') || password.contains('\0') {
        return 3;
    }
    let user: Vec<u16> = user.encode_utf16().chain(Some(0)).collect();
    let mut password: Vec<u16> = password.encode_utf16().chain(Some(0)).collect();
    let result = unsafe { (bridge.sign_in)(user.as_ptr(), password.as_ptr()) };
    for ch in &mut password {
        unsafe {
            std::ptr::write_volatile(ch, 0);
        }
    }
    result
}
/// A newly connected RDP viewer also revokes existing browser access. Cache the
/// query briefly, rather than enumerate Windows sessions for every video packet.
pub fn available() -> bool {
    static CHECK: Mutex<Option<(Instant, bool)>> = Mutex::new(None);
    let mut check = CHECK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, available)) = *check {
        if at.elapsed() < Duration::from_millis(200) {
            return available;
        }
    }
    let available = bridge().is_some_and(|b| unsafe { (b.busy)() == 0 });
    *check = Some((Instant::now(), available));
    available
}
