//! Category: unit (no external services)
//!
//! Operator- and owner-facing text is a product surface, so the sources that
//! produce it are held to one mechanical rule.

use std::path::{Path, PathBuf};

/// A run of spaces inside a string literal is almost always a wrapped line
/// whose `\` continuation was lost: rustfmt joins the literal back onto one
/// line and the indentation of the continued line becomes part of the message.
/// The result reaches an owner as "permits approval only until
/// {n}" with thirty spaces in the middle. It has happened twice, in both
/// directions -- writing the continuation and then having fmt eat it -- so the
/// check is mechanical rather than a habit.
///
/// Write wrapped messages as `concat!("first half ", "second half")`, which is
/// stable under fmt.
#[test]
fn no_message_string_carries_a_run_of_spaces() {
    let mut offenders = Vec::new();
    for file in rust_sources(Path::new(env!("CARGO_MANIFEST_DIR"))) {
        let text = std::fs::read_to_string(&file).unwrap();
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            // Only the content of string literals matters, and a line of
            // aligned code or a table of constants is not one.
            if trimmed.starts_with("//") || !line.contains('"') {
                continue;
            }
            for literal in string_literals(line) {
                // A literal carrying a newline is a block of plan or table
                // text, where aligned columns are the point. A wrapped
                // sentence never has one at the seam.
                if literal.contains("\\n") {
                    continue;
                }
                if literal.contains("   ") && !literal.trim().is_empty() {
                    offenders.push(format!(
                        "{}:{}: {}",
                        file.display(),
                        number + 1,
                        literal.trim()
                    ));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these string literals carry a run of spaces, which is what a lost `\\` \
         line continuation looks like; use concat!(\"a \", \"b\") instead:\n{}",
        offenders.join("\n")
    );
}

/// Every `"..."` on one line, contents only, skipping escaped quotes. Raw
/// strings and multi-line literals are not scanned: this is a lint, not a
/// parser, and the bug it looks for only appears on a joined single line.
fn string_literals(line: &str) -> Vec<String> {
    let bytes: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != '"' {
            index += 1;
            continue;
        }
        // `r"..."` and `r#"..."#` may legitimately hold aligned text.
        if index > 0 && (bytes[index - 1] == 'r' || bytes[index - 1] == '#') {
            return Vec::new();
        }
        let mut content = String::new();
        index += 1;
        while index < bytes.len() && bytes[index] != '"' {
            if bytes[index] == '\\' {
                // Kept verbatim so an escape such as `\n` is visible to the
                // caller's checks rather than silently dropped.
                content.push(bytes[index]);
                if let Some(escaped) = bytes.get(index + 1) {
                    content.push(*escaped);
                }
                index += 2;
                continue;
            }
            content.push(bytes[index]);
            index += 1;
        }
        index += 1;
        out.push(content);
    }
    out
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                out.push(path);
            }
        }
    }
    out
}
