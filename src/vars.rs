// Simple compile-time variable substitution: `set <name> = "<value>"`
// lines are extracted before lexing, and any `$<name>` occurrence
// elsewhere in the script is textually replaced with that value.
//
// This is NOT a runtime variable system — a value can't depend on a
// scan result, only on an earlier `set` in the same script. Keeping it
// this simple means the lexer, parser, and interpreter need zero
// changes: substitution happens once, before any of them ever see the
// source. The alternative (deferring every numeric field's parsing to
// execution time so $vars could appear anywhere, including inside
// values the parser currently reads as u16 immediately) would be a
// much larger, riskier change touching many files for a feature this
// project doesn't need to be that general.
//
// Known limitations: no escaping for a literal `$` character, and
// commented-out `set` lines (`# set x = "y"`) are correctly ignored
// only because they don't start with "set " after trimming — a `set`
// statement appearing mid-line after other content is not supported,
// only as the first thing on a line.

use std::collections::HashMap;

pub fn substitute_variables(source: &str) -> Result<String, String> {
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut output_lines = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("set ") {
            let (name, value) = parse_set_line(rest)?;
            vars.insert(name, value);
            continue; // `set` lines are consumed here, never passed to the lexer
        }
        output_lines.push(line.to_string());
    }

    let mut result = output_lines.join("\n");

    // Longest names first, so "$port" can't accidentally match as a
    // prefix of "$port_range" and substitute wrong.
    let mut names: Vec<&String> = vars.keys().collect();
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    for name in names {
        let placeholder = format!("${}", name);
        result = result.replace(&placeholder, &vars[name]);
    }

    // Anything still starting with $ after substitution is an undefined
    // variable reference — fail clearly rather than silently passing a
    // literal "$typo" through to the parser as a bare word.
    if let Some(pos) = result.find('$') {
        let snippet: String = result[pos..].chars().take(30).collect();
        return Err(format!("undefined variable reference near '{}'", snippet));
    }

    Ok(result)
}

fn parse_set_line(rest: &str) -> Result<(String, String), String> {
    let rest = rest.trim();
    let eq_pos = rest.find('=').ok_or_else(|| {
        format!(
            "invalid 'set' statement '{}': expected 'set name = \"value\"'",
            rest
        )
    })?;
    let name = rest[..eq_pos].trim().to_string();
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(format!("invalid variable name '{}'", name));
    }
    let value_part = rest[eq_pos + 1..].trim();
    let value = value_part
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| {
            format!(
                "invalid 'set' statement: value must be a quoted string, got '{}'",
                value_part
            )
        })?;
    Ok((name, value.to_string()))
}
