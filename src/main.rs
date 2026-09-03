mod ast;
mod backend;
mod http;
mod interpreter;
mod ip;
mod lexer;
mod parallel;
mod parser;
mod report;
mod scan;
mod webchecks;

use interpreter::Interpreter;
use lexer::Lexer;
use parser::Parser;
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: omega <script.omega>");
        return ExitCode::FAILURE;
    }

    let path = &args[1];
    let source = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not read '{}': {}", path, e);
            return ExitCode::FAILURE;
        }
    };

    match run(&source) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(source: &str) -> Result<(), String> {
    let tokens = Lexer::new(source).tokenize()?;
    let program = Parser::new(tokens).parse_program()?;
    let mut interp = Interpreter::new();
    interp.run(&program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexes_basic_script() {
        let src = "target 192.168.1.1\ndiscover hosts\nscan ports\nreport\n";
        let tokens = Lexer::new(src).tokenize().unwrap();
        assert!(tokens.contains(&lexer::Token::Word("target".to_string())));
        assert!(tokens.contains(&lexer::Token::Word("192.168.1.1".to_string())));
    }

    #[test]
    fn parses_milestone_script() {
        let src = "target 192.168.1.1\n\ndiscover hosts\nscan ports\nidentify services\n\nreport\n";
        let tokens = Lexer::new(src).tokenize().unwrap();
        let program = Parser::new(tokens).parse_program().unwrap();
        assert_eq!(program.len(), 5);
    }

    #[test]
    fn parses_scan_block_with_options() {
        let src = "target 10.0.0.1\nscan ports {\n    ports 1-1024\n    services\n    timeout 3s\n}\n";
        let tokens = Lexer::new(src).tokenize().unwrap();
        let program = Parser::new(tokens).parse_program().unwrap();
        match &program[1] {
            ast::Stmt::ScanPorts { options } => {
                assert_eq!(options.ports.as_deref(), Some("1-1024"));
                assert!(options.services);
                assert_eq!(options.timeout_secs, Some(3));
            }
            other => panic!("expected ScanPorts, got {:?}", other),
        }
    }

    #[test]
    fn parses_assessment_block() {
        let src = "assessment \"internal-network\" {\n    target 192.168.1.0/24\n    discover hosts\n    report\n}\n";
        let tokens = Lexer::new(src).tokenize().unwrap();
        let program = Parser::new(tokens).parse_program().unwrap();
        match &program[0] {
            ast::Stmt::Assessment { name, body } => {
                assert_eq!(name, "internal-network");
                assert_eq!(body.len(), 3);
            }
            other => panic!("expected Assessment, got {:?}", other),
        }
    }

    #[test]
    fn rejects_out_of_scope_target_implicitly() {
        // authorized_scope defaults to the first target, so a script that
        // never widens scope and only ever discovers within it should run
        // cleanly. This test just checks parsing succeeds; scope
        // enforcement itself is exercised via the ip module below.
        let src = "authorized_scope 192.168.1.0/24\ntarget 192.168.1.1\ndiscover\n";
        let tokens = Lexer::new(src).tokenize().unwrap();
        let program = Parser::new(tokens).parse_program().unwrap();
        assert_eq!(program.len(), 3);
    }

    #[test]
    fn cidr_contains_respects_prefix() {
        let scope = ip::Cidr::parse("192.168.1.0/24").unwrap();
        let inside = ip::parse_ipv4("192.168.1.55").unwrap();
        let outside = ip::parse_ipv4("8.8.8.8").unwrap();
        assert!(scope.contains(inside));
        assert!(!scope.contains(outside));
    }
}
