//! Module utilitaire pour gérer les différences de VaList entre systèmes d'exploitation

use core::ffi::VaList;

/// Fonction utilitaire pour gérer les différences de VaList entre systèmes d'exploitation
/// Sur CascadeOS, on utilise le VaList standard de Rust sans transformation supplémentaire
pub fn va_to_va_list<'a>(va_list: VaList<'a>) -> VaList<'a> {
    // On ne peut pas vraiment "convertir" un VaList en lui-même, mais cette fonction
    // sert de point d'abstraction pour gérer les différences entre systèmes d'exploitation
    unsafe {
        va_list.with_copy(|copy| copy)
    }
}