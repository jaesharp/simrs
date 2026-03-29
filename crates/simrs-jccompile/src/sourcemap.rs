//! Source map: maps bytecode PC offsets to source file locations.
//!
//! When the compiler emits bytecode, it records which source line and
//! column each instruction came from. This source map can be serialised
//! to a `.jvamap` text format and used by debuggers, disassemblers, and
//! error reporters to show the original source location.
//!
//! # `.jvamap` Text Format
//!
//! ```text
//! # jvac source map v1
//! # source: Counter.java
//! # aid: A0 00 00 00 62 01 01
//! method 0 "process"
//! 0000 12:5
//! 0002 12:25
//! 0004 13:9
//! method 1 "install"
//! 0000 8:5
//! ```

use alloc::string::String;
use alloc::vec::Vec;

/// Source map: maps bytecode PC offsets to source file locations.
#[derive(Debug, Clone)]
pub struct SourceMap {
    /// Source file name (e.g. "Counter.java").
    pub source_file: String,
    /// Package AID bytes.
    pub package_aid: Vec<u8>,
    /// Per-method source mappings.
    pub methods: Vec<MethodMap>,
}

/// Source mapping for a single method.
#[derive(Debug, Clone)]
pub struct MethodMap {
    /// Method name (e.g. "process", "install").
    pub name: String,
    /// PC-to-source entries, sorted by PC.
    pub entries: Vec<SourceEntry>,
}

/// A single mapping from a bytecode PC to a source location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceEntry {
    /// Bytecode program counter offset.
    pub pc: u16,
    /// Source line number (1-based).
    pub line: u32,
    /// Source column number (1-based).
    pub column: u32,
}

impl SourceMap {
    /// Create a new empty source map for the given source file and AID.
    pub fn new(source_file: &str, aid: &[u8]) -> Self {
        Self {
            source_file: String::from(source_file),
            package_aid: Vec::from(aid),
            methods: Vec::new(),
        }
    }

    /// Add a method to the source map. Returns the method index.
    pub fn add_method(&mut self, name: &str) -> usize {
        let idx = self.methods.len();
        self.methods.push(MethodMap {
            name: String::from(name),
            entries: Vec::new(),
        });
        idx
    }

    /// Add a source entry for the given method.
    ///
    /// # Panics
    ///
    /// Panics if `method` is out of range.
    pub fn add_entry(&mut self, method: usize, pc: u16, line: u32, col: u32) {
        self.methods[method].entries.push(SourceEntry {
            pc,
            line,
            column: col,
        });
    }

    /// Look up the source location for a given method and PC.
    ///
    /// Returns the `(line, column)` of the entry with the largest PC that
    /// does not exceed the given PC, or `None` if no entry applies.
    pub fn lookup(&self, method: usize, pc: u16) -> Option<(u32, u32)> {
        let method_map = self.methods.get(method)?;
        let mut best: Option<&SourceEntry> = None;
        for entry in &method_map.entries {
            if entry.pc <= pc {
                match best {
                    Some(b) if b.pc > entry.pc => {}
                    _ => best = Some(entry),
                }
            }
        }
        best.map(|e| (e.line, e.column))
    }

    /// Serialize to `.jvamap` text format.
    pub fn to_text(&self) -> String {
        use core::fmt::Write;
        let mut out = String::new();

        let _ = writeln!(out, "# jvac source map v1");
        let _ = writeln!(out, "# source: {}", self.source_file);

        // Format AID as space-separated hex bytes.
        let _ = write!(out, "# aid:");
        for (i, b) in self.package_aid.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, " {:02X}", b);
            } else {
                let _ = write!(out, " {:02X}", b);
            }
        }
        let _ = writeln!(out);

        for (idx, method) in self.methods.iter().enumerate() {
            let _ = writeln!(out, "method {} \"{}\"", idx, method.name);
            for entry in &method.entries {
                let _ = writeln!(
                    out,
                    "{:04X} {}:{}",
                    entry.pc, entry.line, entry.column
                );
            }
        }

        out
    }

    /// Parse from `.jvamap` text format.
    ///
    /// # Errors
    ///
    /// Returns an error message if the text is malformed.
    pub fn from_text(text: &str) -> Result<Self, String> {
        let mut source_file = String::new();
        let mut package_aid: Vec<u8> = Vec::new();
        let mut methods: Vec<MethodMap> = Vec::new();
        let mut current_method: Option<usize> = None;

        for (line_num, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Header comments.
            if trimmed.starts_with("# source:") {
                source_file = String::from(trimmed["# source:".len()..].trim());
                continue;
            }
            if trimmed.starts_with("# aid:") {
                let aid_str = trimmed["# aid:".len()..].trim();
                package_aid = Vec::new();
                for hex_byte in aid_str.split_whitespace() {
                    let val = u8::from_str_radix(hex_byte, 16).map_err(|e| {
                        alloc::format!(
                            "line {}: invalid AID hex byte '{}': {}",
                            line_num + 1,
                            hex_byte,
                            e
                        )
                    })?;
                    package_aid.push(val);
                }
                continue;
            }
            if trimmed.starts_with('#') {
                // Other comment lines (e.g. "# jvac source map v1").
                continue;
            }

            // Method declaration: method <idx> "<name>"
            if trimmed.starts_with("method ") {
                let rest = &trimmed["method ".len()..];
                // Parse: idx "name"
                let quote_start = rest
                    .find('"')
                    .ok_or_else(|| alloc::format!("line {}: missing method name", line_num + 1))?;
                let quote_end = rest[quote_start + 1..]
                    .find('"')
                    .ok_or_else(|| {
                        alloc::format!("line {}: unterminated method name", line_num + 1)
                    })?;
                let name = &rest[quote_start + 1..quote_start + 1 + quote_end];
                let idx = methods.len();
                methods.push(MethodMap {
                    name: String::from(name),
                    entries: Vec::new(),
                });
                current_method = Some(idx);
                continue;
            }

            // Source entry: XXXX line:col
            if let Some(method_idx) = current_method {
                // Parse "XXXX line:col"
                let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
                if parts.len() != 2 {
                    return Err(alloc::format!(
                        "line {}: expected 'XXXX line:col'",
                        line_num + 1
                    ));
                }
                let pc = u16::from_str_radix(parts[0], 16).map_err(|e| {
                    alloc::format!("line {}: invalid PC '{}': {}", line_num + 1, parts[0], e)
                })?;
                let loc_parts: Vec<&str> = parts[1].splitn(2, ':').collect();
                if loc_parts.len() != 2 {
                    return Err(alloc::format!(
                        "line {}: expected 'line:col' in '{}'",
                        line_num + 1,
                        parts[1]
                    ));
                }
                let line = parse_u32(loc_parts[0], line_num)?;
                let col = parse_u32(loc_parts[1], line_num)?;

                methods[method_idx].entries.push(SourceEntry {
                    pc,
                    line,
                    column: col,
                });
            } else {
                return Err(alloc::format!(
                    "line {}: source entry before any method declaration",
                    line_num + 1
                ));
            }
        }

        Ok(Self {
            source_file,
            package_aid,
            methods,
        })
    }
}

/// Parse a u32 from a string, with a nice error message.
fn parse_u32(s: &str, line_num: usize) -> Result<u32, String> {
    s.parse::<u32>().map_err(|e| {
        alloc::format!(
            "line {}: invalid number '{}': {}",
            line_num + 1,
            s,
            e
        )
    })
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn new_source_map_is_empty() {
        let sm = SourceMap::new("Test.java", &[0xA0, 0x00]);
        assert_eq!(sm.source_file, "Test.java");
        assert_eq!(sm.package_aid, &[0xA0, 0x00]);
        assert!(sm.methods.is_empty());
    }

    #[test]
    fn add_method_returns_index() {
        let mut sm = SourceMap::new("Test.java", &[]);
        let idx0 = sm.add_method("process");
        let idx1 = sm.add_method("install");
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(sm.methods.len(), 2);
        assert_eq!(sm.methods[0].name, "process");
        assert_eq!(sm.methods[1].name, "install");
    }

    #[test]
    fn add_entry_and_lookup() {
        let mut sm = SourceMap::new("Test.java", &[]);
        let m = sm.add_method("process");
        sm.add_entry(m, 0, 10, 5);
        sm.add_entry(m, 4, 11, 9);
        sm.add_entry(m, 8, 12, 1);

        // Exact match.
        assert_eq!(sm.lookup(m, 0), Some((10, 5)));
        assert_eq!(sm.lookup(m, 4), Some((11, 9)));
        assert_eq!(sm.lookup(m, 8), Some((12, 1)));

        // Between entries -- returns the preceding entry.
        assert_eq!(sm.lookup(m, 2), Some((10, 5)));
        assert_eq!(sm.lookup(m, 6), Some((11, 9)));

        // After last entry.
        assert_eq!(sm.lookup(m, 100), Some((12, 1)));
    }

    #[test]
    fn lookup_empty_method() {
        let mut sm = SourceMap::new("Test.java", &[]);
        let m = sm.add_method("empty");
        assert_eq!(sm.lookup(m, 0), None);
    }

    #[test]
    fn lookup_invalid_method() {
        let sm = SourceMap::new("Test.java", &[]);
        assert_eq!(sm.lookup(99, 0), None);
    }

    #[test]
    fn serialize_roundtrip() {
        let mut sm = SourceMap::new("Counter.java", &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01]);
        let m0 = sm.add_method("process");
        sm.add_entry(m0, 0x0000, 12, 5);
        sm.add_entry(m0, 0x0002, 12, 25);
        sm.add_entry(m0, 0x0004, 13, 9);
        let m1 = sm.add_method("install");
        sm.add_entry(m1, 0x0000, 8, 5);

        let text = sm.to_text();

        // Verify text contains expected content.
        assert!(text.contains("# jvac source map v1"));
        assert!(text.contains("# source: Counter.java"));
        assert!(text.contains("# aid: A0 00 00 00 62 01 01"));
        assert!(text.contains("method 0 \"process\""));
        assert!(text.contains("0000 12:5"));
        assert!(text.contains("0002 12:25"));
        assert!(text.contains("0004 13:9"));
        assert!(text.contains("method 1 \"install\""));

        // Parse back.
        let sm2 = SourceMap::from_text(&text).unwrap();
        assert_eq!(sm2.source_file, "Counter.java");
        assert_eq!(sm2.package_aid, &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01]);
        assert_eq!(sm2.methods.len(), 2);
        assert_eq!(sm2.methods[0].name, "process");
        assert_eq!(sm2.methods[0].entries.len(), 3);
        assert_eq!(sm2.methods[1].name, "install");
        assert_eq!(sm2.methods[1].entries.len(), 1);

        // Verify lookups match.
        assert_eq!(sm2.lookup(0, 0x0000), Some((12, 5)));
        assert_eq!(sm2.lookup(0, 0x0002), Some((12, 25)));
        assert_eq!(sm2.lookup(0, 0x0004), Some((13, 9)));
        assert_eq!(sm2.lookup(1, 0x0000), Some((8, 5)));
    }

    #[test]
    fn serialize_empty_source_map() {
        let sm = SourceMap::new("Empty.java", &[]);
        let text = sm.to_text();
        assert!(text.contains("# source: Empty.java"));
        assert!(text.contains("# aid:"));

        let sm2 = SourceMap::from_text(&text).unwrap();
        assert_eq!(sm2.source_file, "Empty.java");
        assert!(sm2.package_aid.is_empty());
        assert!(sm2.methods.is_empty());
    }

    #[test]
    fn serialize_multiple_methods() {
        let mut sm = SourceMap::new("Multi.java", &[0xFF]);
        let m0 = sm.add_method("alpha");
        sm.add_entry(m0, 0, 1, 1);
        sm.add_entry(m0, 2, 2, 1);
        let m1 = sm.add_method("beta");
        sm.add_entry(m1, 0, 10, 1);
        let m2 = sm.add_method("gamma");
        sm.add_entry(m2, 0, 20, 5);
        sm.add_entry(m2, 4, 21, 5);

        let text = sm.to_text();
        let sm2 = SourceMap::from_text(&text).unwrap();

        assert_eq!(sm2.methods.len(), 3);
        assert_eq!(sm2.methods[0].name, "alpha");
        assert_eq!(sm2.methods[1].name, "beta");
        assert_eq!(sm2.methods[2].name, "gamma");

        assert_eq!(sm2.lookup(0, 0), Some((1, 1)));
        assert_eq!(sm2.lookup(0, 2), Some((2, 1)));
        assert_eq!(sm2.lookup(1, 0), Some((10, 1)));
        assert_eq!(sm2.lookup(2, 0), Some((20, 5)));
        assert_eq!(sm2.lookup(2, 4), Some((21, 5)));
    }

    #[test]
    fn parse_error_bad_hex() {
        let text = "# jvac source map v1\n# source: X.java\n# aid: ZZ\n";
        let result = SourceMap::from_text(text);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid AID hex byte"));
    }

    #[test]
    fn parse_error_entry_before_method() {
        let text = "# jvac source map v1\n0000 1:1\n";
        let result = SourceMap::from_text(text);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("source entry before any method declaration"));
    }

    #[test]
    fn parse_error_bad_pc() {
        let text = "# jvac source map v1\nmethod 0 \"foo\"\nXXXX 1:1\n";
        let result = SourceMap::from_text(text);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid PC"));
    }

    #[test]
    fn parse_error_bad_line_number() {
        let text = "# jvac source map v1\nmethod 0 \"foo\"\n0000 abc:1\n";
        let result = SourceMap::from_text(text);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid number"));
    }

    #[test]
    fn parse_error_missing_colon() {
        let text = "# jvac source map v1\nmethod 0 \"foo\"\n0000 12\n";
        let result = SourceMap::from_text(text);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 'line:col'"));
    }

    #[test]
    fn lookup_returns_last_entry_at_or_before_pc() {
        let mut sm = SourceMap::new("Test.java", &[]);
        let m = sm.add_method("test");
        sm.add_entry(m, 10, 5, 1);
        sm.add_entry(m, 20, 10, 1);

        // Before any entry.
        assert_eq!(sm.lookup(m, 5), None);
        // At first entry.
        assert_eq!(sm.lookup(m, 10), Some((5, 1)));
        // Between entries.
        assert_eq!(sm.lookup(m, 15), Some((5, 1)));
        // At second entry.
        assert_eq!(sm.lookup(m, 20), Some((10, 1)));
        // After second entry.
        assert_eq!(sm.lookup(m, 30), Some((10, 1)));
    }

    #[test]
    fn double_roundtrip() {
        // Parse -> serialize -> parse again -> compare.
        let text = "\
# jvac source map v1
# source: Test.java
# aid: A0 FF
method 0 \"main\"
0000 1:1
0005 2:3
method 1 \"helper\"
0000 10:1
";
        let sm1 = SourceMap::from_text(text).unwrap();
        let text2 = sm1.to_text();
        let sm2 = SourceMap::from_text(&text2).unwrap();

        assert_eq!(sm1.source_file, sm2.source_file);
        assert_eq!(sm1.package_aid, sm2.package_aid);
        assert_eq!(sm1.methods.len(), sm2.methods.len());
        for (m1, m2) in sm1.methods.iter().zip(sm2.methods.iter()) {
            assert_eq!(m1.name, m2.name);
            assert_eq!(m1.entries.len(), m2.entries.len());
            for (e1, e2) in m1.entries.iter().zip(m2.entries.iter()) {
                assert_eq!(e1, e2);
            }
        }
    }
}
