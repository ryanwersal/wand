use clap::ValueEnum;
use serde_json::{Value, json};

use crate::Error;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum OutputFormat {
    Json,
    Yaml,
    Table,
}

impl OutputFormat {
    pub fn from_process_args() -> Self {
        let args = std::env::args().collect::<Vec<_>>();
        for window in args.windows(2) {
            if window[0] == "--output" {
                return match window[1].as_str() {
                    "yaml" => Self::Yaml,
                    "table" => Self::Table,
                    _ => Self::Json,
                };
            }
        }
        if let Some(value) = args.iter().find_map(|arg| arg.strip_prefix("--output=")) {
            return match value {
                "yaml" => Self::Yaml,
                "table" => Self::Table,
                _ => Self::Json,
            };
        }
        Self::Json
    }

    pub fn render(self, value: &Value, compact: bool) -> Result<String, String> {
        match self {
            Self::Json if compact => serde_json::to_string(value).map_err(|e| e.to_string()),
            Self::Json => serde_json::to_string_pretty(value).map_err(|e| e.to_string()),
            Self::Yaml => serde_yaml::to_string(value).map_err(|e| e.to_string()),
            Self::Table => Ok(render_table(value)),
        }
    }

    pub fn render_error(self, error: &Error) -> String {
        let mut value = json!({
            "schema_version": "1",
            "error": {"code": error.code(), "message": error.to_string()},
        });
        if let Some(details) = error.details() {
            value["error"]["details"] = details.clone();
        }
        let format = if matches!(self, Self::Table) {
            Self::Json
        } else {
            self
        };
        format
            .render(&value, false)
            .unwrap_or_else(|_| error.to_string())
    }
}

fn render_table(value: &Value) -> String {
    let data = &value["data"];
    let rows = data
        .as_array()
        .map(|rows| rows.iter().collect::<Vec<_>>())
        .unwrap_or_else(|| vec![data]);
    let columns = [
        "id",
        "name",
        "title",
        "severity",
        "status",
        "type",
        "updatedAt",
    ];
    let visible = columns
        .into_iter()
        .filter(|column| rows.iter().any(|row| !row[*column].is_null()))
        .collect::<Vec<_>>();
    if visible.is_empty() {
        return serde_json::to_string_pretty(data).unwrap_or_else(|_| data.to_string());
    }
    let mut widths = visible
        .iter()
        .map(|column| column.len())
        .collect::<Vec<_>>();
    let rendered = rows
        .iter()
        .map(|row| {
            visible
                .iter()
                .map(|column| scalar(&row[*column]))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    for row in &rendered {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.len().min(60));
        }
    }
    let line = |cells: Vec<String>| {
        cells
            .into_iter()
            .enumerate()
            .map(|(index, cell)| {
                format!(
                    "{:<width$}",
                    truncate(&cell, widths[index]),
                    width = widths[index]
                )
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut lines = vec![line(
        visible
            .iter()
            .map(|value| value.to_ascii_uppercase())
            .collect(),
    )];
    lines.push(
        widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join("  "),
    );
    lines.extend(rendered.into_iter().map(line));
    lines.join("\n")
}

fn scalar(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value
            .chars()
            .map(|character| {
                if character.is_control() || is_bidi_control(character) {
                    ' '
                } else {
                    character
                }
            })
            .collect(),
        other => other.to_string(),
    }
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    value
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>()
        + "…"
}

pub fn envelope(data: Value, meta: Value) -> Value {
    json!({"schema_version":"1","data":data,"meta":meta})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_strips_terminal_and_bidi_controls() {
        let value = envelope(
            json!([{"id":"safe\n\u{1b}[31m\u{202e}spoof","severity":"HIGH"}]),
            json!({}),
        );
        let rendered = render_table(&value);
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(rendered.contains("safe"));
        assert!(rendered.contains("[31m"));
        assert!(rendered.contains("spoof"));
    }

    #[test]
    fn truncation_is_unicode_safe() {
        assert_eq!(truncate("ééé", 3), "ééé");
        assert_eq!(truncate("éééé", 3), "éé…");
    }
}
