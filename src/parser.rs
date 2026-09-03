use crate::ast::{Program, ReportDestination, ReportFormat, ScanOptions, Stmt};
use crate::lexer::Token;

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    pub fn parse_program(&mut self) -> Result<Program, String> {
        let mut stmts = Vec::new();
        self.skip_newlines();
        while !self.at_eof() {
            stmts.push(self.parse_stmt()?);
            self.skip_newlines();
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, String> {
        let keyword = self.expect_word("a statement keyword (target, discover, scan, identify, report, authorized_scope, assessment)")?;

        match keyword.as_str() {
            "target" => {
                let addr = self.expect_word("a target address or CIDR (e.g. 192.168.1.0/24)")?;
                Ok(Stmt::Target(addr))
            }
            "authorized_scope" => {
                let addr = self.expect_word("an authorized scope address or CIDR")?;
                Ok(Stmt::AuthorizedScope(addr))
            }
            "discover" => {
                // "hosts" is optional, purely readable sugar: "discover"
                // and "discover hosts" parse to the same statement.
                let _ = self.match_word("hosts");
                Ok(Stmt::Discover)
            }
            "scan" => {
                self.expect_exact_word("ports")?;
                let options = if self.check(&Token::LBrace) {
                    self.parse_scan_block()?
                } else {
                    ScanOptions::default()
                };
                Ok(Stmt::ScanPorts { options })
            }
            "identify" => {
                self.expect_exact_word("services")?;
                Ok(Stmt::IdentifyServices)
            }
            "report" => {
                if self.match_word("to") {
                    let path = self.expect_string("a report file path in quotes")?;
                    let format = if path.ends_with(".json") {
                        ReportFormat::Json
                    } else if path.ends_with(".html") || path.ends_with(".htm") {
                        ReportFormat::Html
                    } else {
                        return Err(format!("unsupported report format for '{}': expected .json or .html", path));
                    };
                    Ok(Stmt::Report { destination: Some(ReportDestination { path, format }) })
                } else {
                    Ok(Stmt::Report { destination: None })
                }
            }
            "assessment" => {
                let name = self.expect_string("an assessment name in quotes")?;
                self.expect(&Token::LBrace)?;
                self.skip_newlines();
                let mut body = Vec::new();
                while !self.check(&Token::RBrace) {
                    body.push(self.parse_stmt()?);
                    self.skip_newlines();
                }
                self.expect(&Token::RBrace)?;
                Ok(Stmt::Assessment { name, body })
            }
            other => Err(format!("unknown statement '{}'", other)),
        }
    }

    fn parse_scan_block(&mut self) -> Result<ScanOptions, String> {
        self.expect(&Token::LBrace)?;
        self.skip_newlines();
        let mut opts = ScanOptions::default();

        while !self.check(&Token::RBrace) {
            let key = self.expect_word("a scan option (ports, services, timeout, os_detect, nse_scripts)")?;
            match key.as_str() {
                "ports" => {
                    let range = self.expect_word("a port range (e.g. 1-65535)")?;
                    opts.ports = Some(range);
                }
                "services" => {
                    opts.services = true;
                }
                "os_detect" => {
                    opts.os_detect = true;
                }
                "nse_scripts" => {
                    let category = self.expect_string("an NSE script category, e.g. vuln")?;
                    opts.nse_scripts = Some(category);
                }
                "timeout" => {
                    let raw = self.expect_word("a timeout, e.g. 3s")?;
                    let secs = raw.trim_end_matches('s').parse::<u64>().map_err(|_| {
                        format!("invalid timeout '{}': expected something like '3s'", raw)
                    })?;
                    opts.timeout_secs = Some(secs);
                }
                other => return Err(format!("unknown scan option '{}'", other)),
            }
            self.skip_newlines();
        }
        self.expect(&Token::RBrace)?;
        Ok(opts)
    }

    // --- token helpers ---

    fn at_eof(&self) -> bool {
        matches!(self.tokens.get(self.pos), Some(Token::Eof) | None)
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        if !matches!(t, Token::Eof) {
            self.pos += 1;
        }
        t
    }

    fn check(&self, t: &Token) -> bool {
        self.peek() == t
    }

    fn skip_newlines(&mut self) {
        while self.check(&Token::Newline) {
            self.advance();
        }
    }

    fn expect(&mut self, t: &Token) -> Result<(), String> {
        if self.check(t) {
            self.advance();
            Ok(())
        } else {
            Err(format!("expected {:?}, found {:?}", t, self.peek()))
        }
    }

    fn expect_word(&mut self, what: &str) -> Result<String, String> {
        match self.advance() {
            Token::Word(w) => Ok(w),
            other => Err(format!("expected {}, found {:?}", what, other)),
        }
    }

    fn expect_exact_word(&mut self, expected: &str) -> Result<(), String> {
        let w = self.expect_word(&format!("'{}'", expected))?;
        if w == expected {
            Ok(())
        } else {
            Err(format!("expected '{}', found '{}'", expected, w))
        }
    }

    fn expect_string(&mut self, what: &str) -> Result<String, String> {
        match self.advance() {
            Token::Str(s) => Ok(s),
            other => Err(format!("expected {}, found {:?}", what, other)),
        }
    }

    /// Consumes the next token only if it's the given bare word; returns
    /// whether it matched. Used for optional trailing words like
    /// "discover hosts" vs bare "discover".
    fn match_word(&mut self, word: &str) -> bool {
        if let Token::Word(w) = self.peek() {
            if w == word {
                self.advance();
                return true;
            }
        }
        false
    }
}
