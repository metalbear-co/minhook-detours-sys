//! MinHook Detours bindings generated with `bindgen`.
#![cfg(target_os = "windows")]
#![cfg(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64"))]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

pub type wchar_t = ::std::os::raw::c_ushort;
pub type BOOL = ::std::os::raw::c_int;
pub type LPVOID = *mut ::std::os::raw::c_void;
pub type ULONG_PTR = ::std::os::raw::c_ulonglong;
pub type CHAR = ::std::os::raw::c_char;
pub type WCHAR = wchar_t;
pub type LPCWSTR = *const WCHAR;
pub type LPCSTR = *const CHAR;
pub type HRESULT = ::std::os::raw::c_long;
pub const MH_OK: MH_STATUS = 0;
pub const MH_ERROR_ALREADY_INITIALIZED: MH_STATUS = 1;
pub const MH_ERROR_NOT_INITIALIZED: MH_STATUS = 2;
pub const MH_ERROR_UNABLE_TO_UNINITIALIZE: MH_STATUS = 3;
pub const MH_ERROR_ALREADY_CREATED: MH_STATUS = 4;
pub const MH_ERROR_NOT_CREATED: MH_STATUS = 5;
pub const MH_ERROR_ENABLED: MH_STATUS = 6;
pub const MH_ERROR_DISABLED: MH_STATUS = 7;
pub const MH_ERROR_NOT_EXECUTABLE: MH_STATUS = 8;
pub const MH_ERROR_DETOURS_TRANSACTION_BEGIN: MH_STATUS = 9;
pub const MH_ERROR_DETOURS_TRANSACTION_COMMIT: MH_STATUS = 10;
pub const MH_ERROR_UNSUPPORTED_FUNCTION: MH_STATUS = 11;
pub const MH_ERROR_MEMORY_ALLOC: MH_STATUS = 12;
pub const MH_ERROR_MODULE_NOT_FOUND: MH_STATUS = 13;
pub const MH_ERROR_FUNCTION_NOT_FOUND: MH_STATUS = 14;
pub type MH_STATUS = ::std::os::raw::c_int;
pub const MH_FREEZE_METHOD_ORIGINAL: MH_THREAD_FREEZE_METHOD = 0;
pub const MH_FREEZE_METHOD_FAST_UNDOCUMENTED: MH_THREAD_FREEZE_METHOD = 1;
pub const MH_FREEZE_METHOD_NONE_UNSAFE: MH_THREAD_FREEZE_METHOD = 2;
pub type MH_THREAD_FREEZE_METHOD = ::std::os::raw::c_int;
pub type MH_ERROR_CALLBACK =
    ::std::option::Option<unsafe extern "C" fn(pTarget: LPVOID, detoursResult: HRESULT)>;

#[link(name = "MinHook")]
unsafe extern "C" {
    pub fn MH_Initialize() -> MH_STATUS;
    pub fn MH_Uninitialize() -> MH_STATUS;
    pub fn MH_SetThreadFreezeMethod(method: MH_THREAD_FREEZE_METHOD) -> MH_STATUS;
    pub fn MH_SetBulkOperationMode(
        continueOnError: BOOL,
        errorCallback: MH_ERROR_CALLBACK,
    ) -> MH_STATUS;
    pub fn MH_CreateHook(pTarget: LPVOID, pDetour: LPVOID, ppOriginal: *mut LPVOID) -> MH_STATUS;
    pub fn MH_CreateHookEx(
        hookIdent: ULONG_PTR,
        pTarget: LPVOID,
        pDetour: LPVOID,
        ppOriginal: *mut LPVOID,
    ) -> MH_STATUS;
    pub fn MH_CreateHookApi(
        pszModule: LPCWSTR,
        pszProcName: LPCSTR,
        pDetour: LPVOID,
        ppOriginal: *mut LPVOID,
    ) -> MH_STATUS;
    pub fn MH_CreateHookApiEx(
        pszModule: LPCWSTR,
        pszProcName: LPCSTR,
        pDetour: LPVOID,
        ppOriginal: *mut LPVOID,
        ppTarget: *mut LPVOID,
    ) -> MH_STATUS;
    pub fn MH_RemoveHook(pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_RemoveHookEx(hookIdent: ULONG_PTR, pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_RemoveDisabledHooks() -> MH_STATUS;
    pub fn MH_RemoveDisabledHooksEx(hookIdent: ULONG_PTR) -> MH_STATUS;
    pub fn MH_EnableHook(pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_EnableHookEx(hookIdent: ULONG_PTR, pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_DisableHook(pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_DisableHookEx(hookIdent: ULONG_PTR, pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_QueueEnableHook(pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_QueueEnableHookEx(hookIdent: ULONG_PTR, pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_QueueDisableHook(pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_QueueDisableHookEx(hookIdent: ULONG_PTR, pTarget: LPVOID) -> MH_STATUS;
    pub fn MH_ApplyQueued() -> MH_STATUS;
    pub fn MH_ApplyQueuedEx(hookIdent: ULONG_PTR) -> MH_STATUS;
    pub fn MH_StatusToString(status: MH_STATUS) -> *const ::std::os::raw::c_char;
}
