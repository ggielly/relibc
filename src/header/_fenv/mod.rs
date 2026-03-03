//! `fenv.h` implementation.
//!
//! See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/fenv.h.html>.

use crate::platform::types::c_int;

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/fenv.h.html>.
pub const FE_ALL_EXCEPT: c_int = 0;
/// See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/fenv.h.html>.
pub const FE_TONEAREST: c_int = 0;

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/fenv.h.html>.
pub type fexcept_t = u64;

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/fenv.h.html>.
#[repr(C)]
pub struct fenv_t {
    pub cw: u64,
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/feclearexcept.html>.
// #[unsafe(no_mangle)]
/// Implements feclearexcept.
pub unsafe extern "C" fn feclearexcept(excepts: c_int) -> c_int {
    unimplemented!();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/fegetenv.html>.
// #[unsafe(no_mangle)]
/// Implements fegetenv.
pub unsafe extern "C" fn fegetenv(envp: *mut fenv_t) -> c_int {
    unimplemented!();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/fegetexceptflag.html>.
// #[unsafe(no_mangle)]
/// Implements fegetexceptflag.
pub unsafe extern "C" fn fegetexceptflag(flagp: *mut fexcept_t, excepts: c_int) -> c_int {
    unimplemented!();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/fegetround.html>.
// #[unsafe(no_mangle)]
/// Implements fegetround.
pub unsafe extern "C" fn fegetround() -> c_int {
    FE_TONEAREST
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/feholdexcept.html>.
// #[unsafe(no_mangle)]
/// Implements feholdexcept.
pub unsafe extern "C" fn feholdexcept(envp: *mut fenv_t) -> c_int {
    unimplemented!();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/feraiseexcept.html>.
// #[unsafe(no_mangle)]
/// Implements feraiseexcept.
pub unsafe extern "C" fn feraiseexcept(except: c_int) -> c_int {
    unimplemented!();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/fesetenv.html>.
// #[unsafe(no_mangle)]
/// Implements fesetenv.
pub unsafe extern "C" fn fesetenv(envp: *const fenv_t) -> c_int {
    unimplemented!();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/fesetexceptflag.html>.
// #[unsafe(no_mangle)]
/// Implements fesetexceptflag.
pub unsafe extern "C" fn fesetexceptflag(flagp: *const fexcept_t, excepts: c_int) -> c_int {
    unimplemented!();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/fegetround.html>.
// #[unsafe(no_mangle)]
/// Implements fesetround.
pub unsafe extern "C" fn fesetround(round: c_int) -> c_int {
    unimplemented!();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/fetestexcept.html>.
// #[unsafe(no_mangle)]
/// Implements fetestexcept.
pub unsafe extern "C" fn fetestexcept(excepts: c_int) -> c_int {
    unimplemented!();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/feupdateenv.html>.
// #[unsafe(no_mangle)]
/// Implements feupdateenv.
pub unsafe extern "C" fn feupdateenv(envp: *const fenv_t) -> c_int {
    unimplemented!();
}
