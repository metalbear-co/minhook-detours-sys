use minhook_detours_sys::*;

#[test]
fn simple_detour() {
    static mut ORIGINAL: Option<unsafe extern "system" fn(i32, i32) -> i64> = None;

    unsafe extern "system" fn add_two(lhs: i32, rhs: i32) -> i64 {
        (lhs + rhs) as i64
    }

    unsafe extern "system" fn add_two_hook(lhs: i32, rhs: i32) -> i64 {
        unsafe {
            let original = ORIGINAL.unwrap();

            MH_DisableHook(add_two as _);
            println!("original: {}", original(lhs, rhs));
            MH_EnableHook(add_two as _);
        }

        (lhs - rhs) as i64
    }

    let target = add_two as *mut std::ffi::c_void;
    let detour = add_two_hook as *mut std::ffi::c_void;
    let mut original = std::ptr::null_mut() as *mut std::ffi::c_void;

    unsafe {
        let status = MH_Initialize();
        assert_eq!(status, MH_OK);

        let status = MH_CreateHook(target, detour, &mut original);
        assert_eq!(status, MH_OK);
        assert_ne!(original, std::ptr::null_mut());

        MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);

        ORIGINAL = Some(std::mem::transmute(original));

        let status = MH_EnableHook(target);
        assert_eq!(status, MH_OK);

        // If [`apply_two_hook`] is applied, then the function should turn to subtracting the 2 argument integers
        // `(lhs - rhs)`. Therefore, we expect the result to be `0` (`2 - 2 = 0`).
        let result = add_two(2, 2);
        assert_eq!(result, 0);
    }
}
