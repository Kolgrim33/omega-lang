// Omega lexer.
//
// Omega intentionally uses a very small, shell-like token set. Most tokens
// are just bare "words" (target addresses, keywords, numbers, ranges like
// "1-65535") and the parser decides what they mean based on position. This
// keeps the lexer tiny and lets the language add new keywords without
// touching this file.

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Word(String),
    Str(String),
    LBrace,
    RBrace,
    Newline,
    Eof,
}

pub struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Lexer {
            chars: src.chars().peekable(),
        }
    }

    pub fn tokenize(mut self) -> Result<Vec<Token>, String> {
        let mut tokens = Vec::new();

        loop {
            self.skip_inline_whitespace();

            match self.chars.peek() {
                None => {
                    tokens.push(Token::Eof);
                    break;
                }
                Some('#') => {
                    // Comment: skip to end of line.
                    while let Some(&c) = self.chars.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.chars.next();
                    }
                }
                Some('\n') => {
                    self.chars.next();
                    if tokens.last() != Some(&Token::Newline) {
                        tokens.push(Token::Newline);
                    }
                }
                Some('{') => {
                    self.chars.next();
                    tokens.push(Token::LBrace);
                }
                Some('}') => {
                    self.chars.next();
                    tokens.push(Token::RBrace);
                }
                Some('"') => {
                    tokens.push(self.read_string()?);
                }
                Some(_) => {
                    tokens.push(self.read_word());
                }
            }
        }

        Ok(tokens)
    }

    fn skip_inline_whitespace(&mut self) {
        while let Some(&c) = self.chars.peek() {
            if c == ' ' || c == '\t' || c == '\r' {
                self.chars.next();
            } else {
                break;
            }
        }
    }

    fn read_string(&mut self) -> Result<Token, String> {
        self.chars.next(); // consume opening quote
        let mut s = String::new();
        loop {
            match self.chars.next() {
                Some('"') => break,
                Some(c) => s.push(c),
                None => return Err("unterminated string literal".to_string()),
            }
        }
        Ok(Token::Str(s))
    }

    fn read_word(&mut self) -> Token {
        let mut s = String::new();
        while let Some(&c) = self.chars.peek() {
            if c.is_whitespace() || c == '{' || c == '}' || c == '"' || c == '#' {
                break;
            }
            s.push(c);
            self.chars.next();
        }
        Token::Word(s)
    }
}
