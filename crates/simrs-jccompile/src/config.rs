//! Optimization configuration for the JVA compiler.
//!
//! Controls IR optimization passes, peephole bytecode optimization,
//! per-pattern selection, iteration limits, and compile-time reporting.

use alloc::vec::Vec;

/// Top-level optimization configuration.
#[derive(Debug, Clone)]
pub struct OptConfig {
    /// IR-level optimization settings.
    pub ir: IrConfig,
    /// Peephole bytecode optimization settings.
    pub peephole: PeepholeConfig,
    /// Emit a compile-time report of optimization activity.
    pub report: bool,
}

/// IR optimization pass configuration.
#[derive(Debug, Clone)]
pub struct IrConfig {
    /// Whether IR optimization is enabled.
    pub enabled: bool,
    /// Maximum number of fixed-point iterations.
    pub max_iterations: usize,
}

/// Peephole bytecode optimization configuration.
///
/// When `enabled` is true, only patterns whose flags are set will fire.
/// When `enabled` is false, no peephole optimization is performed.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct PeepholeConfig {
    /// Whether peephole optimization is enabled at all.
    pub enabled: bool,
    /// Maximum number of peephole passes (fixed-point iteration limit).
    pub max_passes: usize,
    /// `sstore_N; sload_N` -> `dup; sstore_N`
    pub store_load_dup: bool,
    /// `sconst_*; pop`, `bspush X; pop`, `sspush X; pop` -> removed
    pub dead_push_pop: bool,
    /// `sneg; sneg` and `ineg; ineg` -> removed
    pub double_negation: bool,
    /// `goto +2` (next instruction) -> removed
    pub goto_next: bool,
    /// `sconst_0; sadd` -> removed
    pub add_zero_identity: bool,
    /// `sstore_N; sstore_N` -> `pop; sstore_N`
    pub dead_store: bool,
}

/// Per-method optimization report collected during compilation.
#[derive(Debug, Clone, Default)]
pub struct MethodReport {
    /// Number of peephole pattern replacements applied.
    pub peephole_changes: usize,
    /// Bytecode size before peephole optimization.
    pub bytes_before: usize,
    /// Bytecode size after peephole optimization.
    pub bytes_after: usize,
}

/// Compile-time optimization report for an entire class.
#[derive(Debug, Clone, Default)]
pub struct OptReport {
    /// Number of IR fixed-point iterations that ran.
    pub ir_iterations: usize,
    /// Per-method peephole reports.
    pub methods: Vec<MethodReport>,
}

impl OptConfig {
    /// All optimizations enabled with default limits.
    pub const fn full() -> Self {
        Self {
            ir: IrConfig::default_config(),
            peephole: PeepholeConfig::all(),
            report: false,
        }
    }

    /// All optimizations disabled.
    pub const fn none() -> Self {
        Self {
            ir: IrConfig::none(),
            peephole: PeepholeConfig::none(),
            report: false,
        }
    }

    /// Peephole only (IR optimization disabled).
    pub const fn peephole_only() -> Self {
        Self {
            ir: IrConfig::none(),
            peephole: PeepholeConfig::all(),
            report: false,
        }
    }
}

impl IrConfig {
    /// Default IR optimization: enabled with 16 iterations.
    pub const fn default_config() -> Self {
        Self {
            enabled: true,
            max_iterations: 16,
        }
    }

    /// IR optimization disabled.
    pub const fn none() -> Self {
        Self {
            enabled: false,
            max_iterations: 0,
        }
    }
}

impl PeepholeConfig {
    /// All peephole patterns enabled with default pass limit.
    pub const fn all() -> Self {
        Self {
            enabled: true,
            max_passes: 64,
            store_load_dup: true,
            dead_push_pop: true,
            double_negation: true,
            goto_next: true,
            add_zero_identity: true,
            dead_store: true,
        }
    }

    /// Peephole optimization disabled.
    pub const fn none() -> Self {
        Self {
            enabled: false,
            max_passes: 0,
            store_load_dup: false,
            dead_push_pop: false,
            double_negation: false,
            goto_next: false,
            add_zero_identity: false,
            dead_store: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_config_has_all_patterns() {
        let cfg = OptConfig::full();
        assert!(cfg.ir.enabled);
        assert_eq!(cfg.ir.max_iterations, 16);
        assert!(cfg.peephole.enabled);
        assert_eq!(cfg.peephole.max_passes, 64);
        assert!(cfg.peephole.store_load_dup);
        assert!(cfg.peephole.dead_push_pop);
        assert!(cfg.peephole.double_negation);
        assert!(cfg.peephole.goto_next);
        assert!(cfg.peephole.add_zero_identity);
        assert!(cfg.peephole.dead_store);
        assert!(!cfg.report);
    }

    #[test]
    fn none_config_disables_everything() {
        let cfg = OptConfig::none();
        assert!(!cfg.ir.enabled);
        assert!(!cfg.peephole.enabled);
        assert!(!cfg.peephole.store_load_dup);
        assert!(!cfg.peephole.dead_push_pop);
        assert!(!cfg.peephole.double_negation);
        assert!(!cfg.peephole.goto_next);
        assert!(!cfg.peephole.add_zero_identity);
        assert!(!cfg.peephole.dead_store);
    }

    #[test]
    fn peephole_only_disables_ir() {
        let cfg = OptConfig::peephole_only();
        assert!(!cfg.ir.enabled);
        assert!(cfg.peephole.enabled);
        assert!(cfg.peephole.store_load_dup);
    }
}
