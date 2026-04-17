//! Integration tests for simrs-jacc source compilation.
//!
//! Tests the full pipeline: Java/JVA source -> parse -> compile -> CAP -> VM execute.

use simrs_jcvm::cap::parse_cap;
use simrs_jcvm::opcodes::ExecResult;

/// Helper: compile source to CAP bytes.
fn compile_source_to_cap(source: &str) -> Vec<u8> {
    let class = simrs_jacc::java_parser::parse_source(source).expect("parse failed");
    let compiled = simrs_jccompile::compile_class(&class).expect("compile failed");
    simrs_jacc::cap::write_cap(&compiled)
}

/// Helper: load CAP into VM and execute method 0.
fn execute_method_0(cap: &[u8]) -> ExecResult {
    let pkg = parse_cap(cap).expect("CAP parse failed");
    let mut vm = simrs_jcvm::JcVM::<4096, 4>::new();
    let idx = vm.load_package(pkg).expect("load failed");
    vm.execute(idx, 0)
}

#[test]
fn compile_constant_return() {
    let source = r"
        public class ConstRet extends Applet {
            public static short process() {
                return 42;
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(42));
}

#[test]
fn compile_zero_return() {
    let source = r"
        public class ZeroRet extends Applet {
            public static short process() {
                return 0;
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(0));
}

#[test]
fn compile_negative_return() {
    let source = r"
        public class NegRet extends Applet {
            public static short process() {
                return -1;
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(-1));
}

#[test]
fn compile_with_locals() {
    let source = r"
        public class Calc extends Applet {
            public static short process() {
                short a = 10;
                short b = 20;
                return (short)(a + b);
            }
        }
    ";
    let class = simrs_jacc::java_parser::parse_source(source).expect("parse failed");
    let compiled = simrs_jccompile::compile_class(&class).expect("compile failed");
    let cap = simrs_jacc::cap::write_cap(&compiled);

    let pkg = parse_cap(&cap).unwrap();
    let mut vm = simrs_jcvm::JcVM::<4096, 4>::new();
    let idx = vm.load_package(pkg).unwrap();
    let result = vm.execute(idx, 0);
    assert_eq!(result, ExecResult::ReturnShort(30));
}

#[test]
fn compile_arithmetic_sub() {
    let source = r"
        public class Sub extends Applet {
            public static short process() {
                short a = 50;
                short b = 15;
                return (short)(a - b);
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(35));
}

#[test]
fn compile_arithmetic_mul() {
    let source = r"
        public class Mul extends Applet {
            public static short process() {
                short a = 6;
                short b = 7;
                return (short)(a * b);
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(42));
}

#[test]
fn compile_if_else_true_branch() {
    let source = r"
        public class IfTrue extends Applet {
            public static short process() {
                short x = 0;
                if (x == 0) {
                    return 1;
                } else {
                    return 2;
                }
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(1));
}

#[test]
fn compile_if_else_false_branch() {
    let source = r"
        public class IfFalse extends Applet {
            public static short process() {
                short x = 1;
                if (x == 0) {
                    return 1;
                } else {
                    return 2;
                }
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(2));
}

#[test]
fn compile_while_loop_sum() {
    let source = r"
        public class WhileSum extends Applet {
            public static short process() {
                short i = 1;
                short sum = 0;
                while (i != 6) {
                    sum = (short)(sum + i);
                    i = (short)(i + 1);
                }
                return sum;
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(15)); // 1+2+3+4+5 = 15
}

#[test]
fn compile_void_return() {
    let source = r"
        public class VoidRet extends Applet {
            public static void process() {
                return;
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnVoid);
}

#[test]
fn parse_complex_class() {
    // Test that a more complex class structure parses without error,
    // even if we can't fully compile all API calls.
    let source = r"
        package com.example;
        import javacard.framework.*;

        public class Wallet extends Applet {
            private short balance;
            private byte[] echoBuffer;

            protected Wallet() {
                balance = 0;
            }

            public static void install(byte[] buf, short offset, byte length) {
                return;
            }

            public void process() {
                short x = 10;
                this.balance = (short)(this.balance + x);
            }
        }
    ";
    let class = simrs_jacc::java_parser::parse_source(source).expect("parse failed");
    assert_eq!(class.fields.len(), 2);
    assert!(class.methods.len() >= 2); // constructor + install + process
}

#[test]
fn compile_large_constant() {
    let source = r"
        public class LargeConst extends Applet {
            public static short process() {
                return 1000;
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(1000));
}

#[test]
fn compile_negation() {
    let source = r"
        public class NegExpr extends Applet {
            public static short process() {
                short x = 7;
                return (short)(-x);
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(-7));
}

#[test]
fn compile_cast_is_transparent() {
    // Verify that (short) cast is a no-op and doesn't break compilation.
    let source = r"
        public class CastTest extends Applet {
            public static short process() {
                short a = 3;
                short b = 4;
                return (short)(a + b);
            }
        }
    ";
    let cap = compile_source_to_cap(source);
    let result = execute_method_0(&cap);
    assert_eq!(result, ExecResult::ReturnShort(7));
}

#[test]
fn compile_multiple_methods() {
    // Ensure we can compile a class with multiple methods and call the second one.
    let source = r"
        public class Multi extends Applet {
            public static short first() {
                return 10;
            }
            public static short second() {
                return 20;
            }
        }
    ";
    let class = simrs_jacc::java_parser::parse_source(source).expect("parse failed");
    let compiled = simrs_jccompile::compile_class(&class).expect("compile failed");
    assert_eq!(compiled.methods.len(), 2);

    let cap = simrs_jacc::cap::write_cap(&compiled);
    let pkg = parse_cap(&cap).unwrap();
    let mut vm = simrs_jcvm::JcVM::<4096, 4>::new();
    let idx = vm.load_package(pkg).unwrap();

    assert_eq!(vm.execute(idx, 0), ExecResult::ReturnShort(10));
    assert_eq!(vm.execute(idx, 1), ExecResult::ReturnShort(20));
}
