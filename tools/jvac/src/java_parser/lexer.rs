//! Tokenizer for Java/JVA source files.
//!
//! Single-pass, character-by-character lexer that produces a flat token stream.
//! Tracks line and column for error reporting.

/// A source location for error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// 1-based line number.
    pub line: usize,
    /// 1-based column number.
    pub col: usize,
}

/// A token produced by the lexer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    // Keywords
    /// `package`
    Package,
    /// `import`
    Import,
    /// `public`
    Public,
    /// `private`
    Private,
    /// `protected`
    Protected,
    /// `static`
    Static,
    /// `final`
    Final,
    /// `class`
    Class,
    /// `extends`
    Extends,
    /// `implements`
    Implements,
    /// `interface`
    Interface,
    /// `void`
    Void,
    /// `byte`
    Byte,
    /// `short`
    Short,
    /// `boolean`
    Boolean,
    /// `int`
    Int,
    /// `if`
    If,
    /// `else`
    Else,
    /// `while`
    While,
    /// `for`
    For,
    /// `return`
    Return,
    /// `new`
    New,
    /// `this`
    This,
    /// `true`
    True,
    /// `false`
    False,
    /// `null`
    Null,
    /// `throw`
    Throw,
    /// `try`
    Try,
    /// `catch`
    Catch,
    /// `switch`
    Switch,
    /// `case`
    Case,
    /// `default`
    Default,
    /// `break`
    Break,
    /// `super`
    Super,
    /// `abstract`
    Abstract,

    // Punctuation
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `;`
    Semicolon,
    /// `,`
    Comma,
    /// `.`
    Dot,
    /// `:`
    Colon,

    // Operators
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Star,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `<=`
    Le,
    /// `>=`
    Ge,
    /// `=`
    Assign,
    /// `+=`
    PlusAssign,
    /// `-=`
    MinusAssign,
    /// `++`
    PlusPlus,
    /// `--`
    MinusMinus,
    /// `&&`
    And,
    /// `||`
    Or,
    /// `!`
    Not,
    /// `&`
    BitAnd,
    /// `|`
    BitOr,
    /// `^`
    BitXor,
    /// `~`
    BitNot,
    /// `<<`
    Shl,
    /// `>>`
    Shr,

    // Literals
    /// Integer literal (decimal or hex).
    IntLit(i64),
    /// String literal.
    StringLit(String),
    /// Character literal.
    CharLit(char),

    // Identifiers
    /// An identifier (variable name, type name, etc.).
    Ident(String),

    // Special
    /// An annotation (`@Override`, `@Applet`, etc.).
    Annotation(String),
    /// End of file.
    Eof,
}

/// A token together with its source location.
#[derive(Debug, Clone)]
pub struct SpannedToken {
    /// The token.
    pub token: Token,
    /// Source location where the token starts.
    pub span: Span,
}

/// Tokenize a Java/JVA source string into a token stream.
///
/// # Errors
///
/// Returns a string error message including line/column on lexer failure.
#[allow(clippy::too_many_lines)]
pub fn tokenize(source: &str) -> Result<Vec<SpannedToken>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = source.chars().collect();
    let len = chars.len();
    let mut pos = 0;
    let mut line: usize = 1;
    let mut col: usize = 1;

    while pos < len {
        let ch = chars[pos];

        // Whitespace.
        if ch.is_ascii_whitespace() {
            if ch == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            pos += 1;
            continue;
        }

        // Single-line comment.
        if ch == '/' && pos + 1 < len && chars[pos + 1] == '/' {
            pos += 2;
            col += 2;
            while pos < len && chars[pos] != '\n' {
                pos += 1;
                col += 1;
            }
            continue;
        }

        // Multi-line comment.
        if ch == '/' && pos + 1 < len && chars[pos + 1] == '*' {
            let start_line = line;
            let start_col = col;
            pos += 2;
            col += 2;
            let mut closed = false;
            while pos + 1 < len {
                if chars[pos] == '*' && chars[pos + 1] == '/' {
                    pos += 2;
                    col += 2;
                    closed = true;
                    break;
                }
                if chars[pos] == '\n' {
                    line += 1;
                    col = 1;
                } else {
                    col += 1;
                }
                pos += 1;
            }
            if !closed {
                return Err(format!(
                    "{start_line}:{start_col}: unterminated block comment"
                ));
            }
            continue;
        }

        let span = Span { line, col };

        // Annotation.
        if ch == '@' {
            pos += 1;
            col += 1;
            let start = pos;
            while pos < len && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_') {
                pos += 1;
                col += 1;
            }
            let name: String = chars[start..pos].iter().collect();
            if name.is_empty() {
                return Err(format!("{}:{}: empty annotation", span.line, span.col));
            }
            tokens.push(SpannedToken {
                token: Token::Annotation(name),
                span,
            });
            continue;
        }

        // String literal.
        if ch == '"' {
            pos += 1;
            col += 1;
            let mut s = String::new();
            let start_line = line;
            let start_col = col;
            loop {
                if pos >= len {
                    return Err(format!(
                        "{start_line}:{start_col}: unterminated string literal"
                    ));
                }
                let c = chars[pos];
                if c == '"' {
                    pos += 1;
                    col += 1;
                    break;
                }
                if c == '\\' && pos + 1 < len {
                    pos += 1;
                    col += 1;
                    let escaped = match chars[pos] {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        '\\' => '\\',
                        '"' => '"',
                        '\'' => '\'',
                        '0' => '\0',
                        other => other,
                    };
                    s.push(escaped);
                    pos += 1;
                    col += 1;
                } else {
                    if c == '\n' {
                        line += 1;
                        col = 1;
                    } else {
                        col += 1;
                    }
                    s.push(c);
                    pos += 1;
                }
            }
            tokens.push(SpannedToken {
                token: Token::StringLit(s),
                span,
            });
            continue;
        }

        // Character literal.
        if ch == '\'' {
            pos += 1;
            col += 1;
            if pos >= len {
                return Err(format!("{}:{}: unterminated char literal", span.line, span.col));
            }
            let c = if chars[pos] == '\\' {
                pos += 1;
                col += 1;
                if pos >= len {
                    return Err(format!("{}:{}: unterminated char escape", span.line, span.col));
                }
                let escaped = match chars[pos] {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '\\' => '\\',
                    '\'' => '\'',
                    '0' => '\0',
                    other => other,
                };
                pos += 1;
                col += 1;
                escaped
            } else {
                let c = chars[pos];
                pos += 1;
                col += 1;
                c
            };
            if pos >= len || chars[pos] != '\'' {
                return Err(format!("{}:{}: unterminated char literal", span.line, span.col));
            }
            pos += 1;
            col += 1;
            tokens.push(SpannedToken {
                token: Token::CharLit(c),
                span,
            });
            continue;
        }

        // Integer literal.
        if ch.is_ascii_digit() {
            if ch == '0' && pos + 1 < len && (chars[pos + 1] == 'x' || chars[pos + 1] == 'X') {
                // Hex literal.
                pos += 2;
                col += 2;
                let hex_start = pos;
                while pos < len && chars[pos].is_ascii_hexdigit() {
                    pos += 1;
                    col += 1;
                }
                if pos == hex_start {
                    return Err(format!(
                        "{}:{}: expected hex digits after 0x", span.line, span.col
                    ));
                }
                let hex_str: String = chars[hex_start..pos].iter().collect();
                let value = i64::from_str_radix(&hex_str, 16).map_err(|e| {
                    format!("{}:{}: invalid hex literal: {e}", span.line, span.col)
                })?;
                // Skip trailing L/l suffix if present.
                if pos < len && (chars[pos] == 'L' || chars[pos] == 'l') {
                    pos += 1;
                    col += 1;
                }
                tokens.push(SpannedToken {
                    token: Token::IntLit(value),
                    span,
                });
            } else {
                // Decimal literal.
                let start = pos;
                while pos < len && chars[pos].is_ascii_digit() {
                    pos += 1;
                    col += 1;
                }
                // Skip trailing L/l suffix if present.
                if pos < len && (chars[pos] == 'L' || chars[pos] == 'l') {
                    pos += 1;
                    col += 1;
                }
                let num_str: String = chars[start..pos].iter().collect();
                let num_str = num_str.trim_end_matches(['L', 'l']);
                let value: i64 = num_str.parse().map_err(|e| {
                    format!("{}:{}: invalid integer literal: {e}", span.line, span.col)
                })?;
                tokens.push(SpannedToken {
                    token: Token::IntLit(value),
                    span,
                });
            }
            continue;
        }

        // Identifiers and keywords.
        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = pos;
            while pos < len && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_') {
                pos += 1;
                col += 1;
            }
            let word: String = chars[start..pos].iter().collect();
            let token = keyword_or_ident(word);
            tokens.push(SpannedToken { token, span });
            continue;
        }

        // Multi-character operators and single-character punctuation.
        let token = lex_punctuation(&chars, &mut pos, &mut col, line)?;
        tokens.push(SpannedToken { token, span });
    }

    tokens.push(SpannedToken {
        token: Token::Eof,
        span: Span { line, col },
    });

    Ok(tokens)
}

/// Convert a word to a keyword token or an identifier.
fn keyword_or_ident(word: String) -> Token {
    match word.as_str() {
        "package" => Token::Package,
        "import" => Token::Import,
        "public" => Token::Public,
        "private" => Token::Private,
        "protected" => Token::Protected,
        "static" => Token::Static,
        "final" => Token::Final,
        "class" => Token::Class,
        "extends" => Token::Extends,
        "implements" => Token::Implements,
        "interface" => Token::Interface,
        "void" => Token::Void,
        "byte" => Token::Byte,
        "short" => Token::Short,
        "boolean" => Token::Boolean,
        "int" => Token::Int,
        "if" => Token::If,
        "else" => Token::Else,
        "while" => Token::While,
        "for" => Token::For,
        "return" => Token::Return,
        "new" => Token::New,
        "this" => Token::This,
        "true" => Token::True,
        "false" => Token::False,
        "null" => Token::Null,
        "throw" => Token::Throw,
        "try" => Token::Try,
        "catch" => Token::Catch,
        "switch" => Token::Switch,
        "case" => Token::Case,
        "default" => Token::Default,
        "break" => Token::Break,
        "super" => Token::Super,
        "abstract" => Token::Abstract,
        _ => Token::Ident(word),
    }
}

/// Lex a punctuation or operator token at the current position.
#[allow(clippy::too_many_lines)]
fn lex_punctuation(
    chars: &[char],
    pos: &mut usize,
    col: &mut usize,
    line: usize,
) -> Result<Token, String> {
    let ch = chars[*pos];
    let len = chars.len();
    let tok = match ch {
        '(' => { *pos += 1; *col += 1; Token::LParen }
        ')' => { *pos += 1; *col += 1; Token::RParen }
        '{' => { *pos += 1; *col += 1; Token::LBrace }
        '}' => { *pos += 1; *col += 1; Token::RBrace }
        '[' => { *pos += 1; *col += 1; Token::LBracket }
        ']' => { *pos += 1; *col += 1; Token::RBracket }
        ';' => { *pos += 1; *col += 1; Token::Semicolon }
        ',' => { *pos += 1; *col += 1; Token::Comma }
        '.' => { *pos += 1; *col += 1; Token::Dot }
        ':' => { *pos += 1; *col += 1; Token::Colon }
        '~' => { *pos += 1; *col += 1; Token::BitNot }
        '^' => { *pos += 1; *col += 1; Token::BitXor }
        '+' => {
            *pos += 1; *col += 1;
            if *pos < len && chars[*pos] == '=' {
                *pos += 1; *col += 1;
                Token::PlusAssign
            } else if *pos < len && chars[*pos] == '+' {
                *pos += 1; *col += 1;
                Token::PlusPlus
            } else {
                Token::Plus
            }
        }
        '-' => {
            *pos += 1; *col += 1;
            if *pos < len && chars[*pos] == '=' {
                *pos += 1; *col += 1;
                Token::MinusAssign
            } else if *pos < len && chars[*pos] == '-' {
                *pos += 1; *col += 1;
                Token::MinusMinus
            } else {
                Token::Minus
            }
        }
        '*' => { *pos += 1; *col += 1; Token::Star }
        '/' => { *pos += 1; *col += 1; Token::Slash }
        '%' => { *pos += 1; *col += 1; Token::Percent }
        '=' => {
            *pos += 1; *col += 1;
            if *pos < len && chars[*pos] == '=' {
                *pos += 1; *col += 1;
                Token::Eq
            } else {
                Token::Assign
            }
        }
        '!' => {
            *pos += 1; *col += 1;
            if *pos < len && chars[*pos] == '=' {
                *pos += 1; *col += 1;
                Token::Ne
            } else {
                Token::Not
            }
        }
        '<' => {
            *pos += 1; *col += 1;
            if *pos < len && chars[*pos] == '=' {
                *pos += 1; *col += 1;
                Token::Le
            } else if *pos < len && chars[*pos] == '<' {
                *pos += 1; *col += 1;
                Token::Shl
            } else {
                Token::Lt
            }
        }
        '>' => {
            *pos += 1; *col += 1;
            if *pos < len && chars[*pos] == '=' {
                *pos += 1; *col += 1;
                Token::Ge
            } else if *pos < len && chars[*pos] == '>' {
                *pos += 1; *col += 1;
                Token::Shr
            } else {
                Token::Gt
            }
        }
        '&' => {
            *pos += 1; *col += 1;
            if *pos < len && chars[*pos] == '&' {
                *pos += 1; *col += 1;
                Token::And
            } else {
                Token::BitAnd
            }
        }
        '|' => {
            *pos += 1; *col += 1;
            if *pos < len && chars[*pos] == '|' {
                *pos += 1; *col += 1;
                Token::Or
            } else {
                Token::BitOr
            }
        }
        _ => {
            return Err(format!("{line}:{}: unexpected character '{ch}'", *col));
        }
    };
    Ok(tok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_simple_class() {
        let src = "public class Foo { }";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::Public);
        assert_eq!(tokens[1].token, Token::Class);
        assert_eq!(tokens[2].token, Token::Ident("Foo".into()));
        assert_eq!(tokens[3].token, Token::LBrace);
        assert_eq!(tokens[4].token, Token::RBrace);
        assert_eq!(tokens[5].token, Token::Eof);
    }

    #[test]
    fn tokenize_hex_literal() {
        let src = "0xFF";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::IntLit(255));
    }

    #[test]
    fn tokenize_decimal_literal() {
        let src = "42";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::IntLit(42));
    }

    #[test]
    fn tokenize_string_literal() {
        let src = r#""hello\n""#;
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::StringLit("hello\n".into()));
    }

    #[test]
    fn tokenize_annotation() {
        let src = "@Override";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::Annotation("Override".into()));
    }

    #[test]
    fn tokenize_operators() {
        let src = "== != <= >= && || + - * / % ++ --";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::Eq);
        assert_eq!(tokens[1].token, Token::Ne);
        assert_eq!(tokens[2].token, Token::Le);
        assert_eq!(tokens[3].token, Token::Ge);
        assert_eq!(tokens[4].token, Token::And);
        assert_eq!(tokens[5].token, Token::Or);
        assert_eq!(tokens[6].token, Token::Plus);
        assert_eq!(tokens[7].token, Token::Minus);
        assert_eq!(tokens[8].token, Token::Star);
        assert_eq!(tokens[9].token, Token::Slash);
        assert_eq!(tokens[10].token, Token::Percent);
        assert_eq!(tokens[11].token, Token::PlusPlus);
        assert_eq!(tokens[12].token, Token::MinusMinus);
    }

    #[test]
    fn tokenize_single_line_comment() {
        let src = "x // comment\ny";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::Ident("x".into()));
        assert_eq!(tokens[1].token, Token::Ident("y".into()));
    }

    #[test]
    fn tokenize_block_comment() {
        let src = "x /* block\ncomment */ y";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::Ident("x".into()));
        assert_eq!(tokens[1].token, Token::Ident("y".into()));
    }

    #[test]
    fn tokenize_cast_syntax() {
        let src = "(short)(x + 1)";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::LParen);
        assert_eq!(tokens[1].token, Token::Short);
        assert_eq!(tokens[2].token, Token::RParen);
        assert_eq!(tokens[3].token, Token::LParen);
        assert_eq!(tokens[4].token, Token::Ident("x".into()));
        assert_eq!(tokens[5].token, Token::Plus);
        assert_eq!(tokens[6].token, Token::IntLit(1));
        assert_eq!(tokens[7].token, Token::RParen);
    }

    #[test]
    fn line_tracking() {
        let src = "a\nb\nc";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].span.line, 1);
        assert_eq!(tokens[1].span.line, 2);
        assert_eq!(tokens[2].span.line, 3);
    }

    #[test]
    fn keywords_vs_identifiers() {
        let src = "class myClass extends Applet";
        let tokens = tokenize(src).unwrap();
        assert_eq!(tokens[0].token, Token::Class);
        assert_eq!(tokens[1].token, Token::Ident("myClass".into()));
        assert_eq!(tokens[2].token, Token::Extends);
        assert_eq!(tokens[3].token, Token::Ident("Applet".into()));
    }
}
