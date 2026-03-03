//! Module utilitaire pour gérer les différences de VaList entre systèmes d'exploitation

use core::ffi::VaList;

/// Fonction utilitaire pour gérer les différences de VaList entre systèmes d'exploitation
/// Sur Strat9-OS, on utilise le VaList standard de Rust sans transformation supplémentaire
pub fn va_to_va_list<'a>(va_list: VaList<'a>) -> VaList<'a> {
    // Strat9 uses the platform va_list ABI directly.
    va_list
}