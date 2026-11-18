//! Compiled desktop archive queries. MCP uses its separate sanitized search.
use crate::{Engine, Exchange};
use anyhow::{anyhow, bail, Context, Result};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

const MAX_QUERY_BYTES: usize = 4096;
const MAX_TERMS: usize = 32;

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrafficFilter {
    #[default]
    All,
    Successful,
    Errors,
    Edited,
}

impl TrafficFilter {
    fn matches(self, exchange: &Exchange) -> bool {
        match self {
            Self::All => true,
            Self::Successful => exchange
                .status
                .is_some_and(|status| (200..300).contains(&status)),
            Self::Errors => exchange.completed && has_error(exchange),
            Self::Edited => exchange.edited,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangePage {
    pub rows: Vec<Exchange>,
    pub next_cursor: Option<String>,
}

impl Engine {
    /// List traffic summaries in archive order, applying both filters before pagination.
    pub fn list_exchange_page(
        &self,
        session_id: &str,
        query: Option<&str>,
        filter: TrafficFilter,
        limit: usize,
        before: Option<&str>,
    ) -> Result<ExchangePage> {
        let db = self.inner.db.lock().unwrap();
        if !db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE id=?1)",
            [session_id],
            |row| row.get::<_, bool>(0),
        )? {
            bail!("Session not found: {session_id}");
        }
        let query = Query::parse(query)?;
        let limit = limit.clamp(1, 1000);
        let boundary = before
            .map(|id| {
                db.query_row(
                    "SELECT started_at, rowid FROM exchanges WHERE id=?1 AND session_id=?2",
                    params![id, session_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .context("Traffic page cursor does not belong to this session")
            })
            .transpose()?;
        let mut statement = db.prepare(if boundary.is_some() {
            "SELECT data FROM exchanges WHERE session_id=?1 AND (started_at,rowid)<(?2,?3)
             ORDER BY started_at DESC,rowid DESC"
        } else {
            "SELECT data FROM exchanges WHERE session_id=?1 ORDER BY started_at DESC,rowid DESC"
        })?;
        let mut entries = match boundary {
            Some((started_at, row_id)) => {
                statement.query(params![session_id, started_at, row_id])?
            }
            None => statement.query([session_id])?,
        };
        let mut page = ExchangePage {
            rows: Vec::new(),
            next_cursor: None,
        };
        while let Some(entry) = entries.next()? {
            let mut exchange: Exchange = serde_json::from_str(entry.get_ref(0)?.as_str()?)?;
            if !filter.matches(&exchange) || !query.matches(&exchange) {
                continue;
            }
            if page.rows.len() == limit {
                page.next_cursor = page.rows.last().map(|row| row.id.clone());
                break;
            }
            exchange.request_body = String::new();
            exchange.response_body = String::new();
            exchange.original_request = None;
            exchange.original_response = None;
            page.rows.push(exchange);
        }
        Ok(page)
    }
}

fn has_error(exchange: &Exchange) -> bool {
    exchange
        .error
        .as_ref()
        .is_some_and(|error| !error.is_empty())
        || exchange.status.is_some_and(|status| status >= 400)
}

pub(crate) enum Query {
    Literal(String),
    Structured(Vec<Predicate>),
}

impl Query {
    pub(crate) fn parse(input: Option<&str>) -> Result<Self> {
        let input = input.unwrap_or("");
        if let Some(literal) = input.strip_prefix("text:") {
            return Ok(Self::Literal(literal.to_lowercase()));
        }
        let Some(expression) = input.strip_prefix("filter:") else {
            return Ok(Self::Literal(input.to_lowercase()));
        };
        if input.len() > MAX_QUERY_BYTES {
            bail!("Invalid search expression: maximum query size is 4096 bytes");
        }
        let mut rest = expression.trim_start();
        let mut predicates = Vec::new();
        while !rest.is_empty() {
            if predicates.len() == MAX_TERMS {
                bail!("Invalid search expression: maximum number of terms is 32");
            }
            let field_end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, '=' | '!' | '>' | '<' | '~'))
                .ok_or_else(|| {
                    anyhow!("Invalid search expression: expected a field and operator")
                })?;
            let field = &rest[..field_end];
            rest = &rest[field_end..];
            let operator = ["!=", ">=", "<=", "~=", "=", ">", "<"]
                .into_iter()
                .find(|operator| rest.starts_with(operator))
                .ok_or_else(|| anyhow!("Invalid search expression: unsupported operator"))?;
            rest = &rest[operator.len()..];
            let (value, remaining) = parse_value(rest)?;
            predicates.push(Predicate::parse(field, operator, value)?);
            rest = remaining.trim_start();
        }
        if predicates.is_empty() {
            bail!("Invalid search expression: expected at least one term");
        }
        Ok(Self::Structured(predicates))
    }

    pub(crate) fn matches(&self, exchange: &Exchange) -> bool {
        match self {
            // Preserve the original whole-string search and its persisted fields.
            Self::Literal(needle) => {
                needle.is_empty()
                    || format!(
                        "{} {} {:?} {} {} {:?} {:?}",
                        exchange.method,
                        exchange.url,
                        exchange.status,
                        exchange.request_body,
                        exchange.response_body,
                        exchange.request_headers,
                        exchange.response_headers
                    )
                    .to_lowercase()
                    .contains(needle)
            }
            Self::Structured(predicates) => predicates.iter().all(|term| term.matches(exchange)),
        }
    }
}

/// A quote must enclose the entire value; only quote and backslash can be escaped.
fn parse_value(input: &str) -> Result<(String, &str)> {
    let mut value = String::new();
    let remaining = if let Some(quoted) = input.strip_prefix('"') {
        let mut chars = quoted.char_indices();
        loop {
            match chars.next() {
                Some((index, '"')) => {
                    let remaining = &quoted[index + 1..];
                    if remaining.starts_with(|c: char| !c.is_whitespace()) {
                        bail!(
                            "Invalid search expression: quoted values must end at a term boundary"
                        );
                    }
                    break remaining;
                }
                Some((_, '\\')) => match chars.next() {
                    Some((_, c @ ('"' | '\\'))) => value.push(c),
                    _ => bail!(
                        "Invalid search expression: only quote and backslash escapes are supported"
                    ),
                },
                Some((_, c)) => value.push(c),
                None => bail!("Invalid search expression: expected a closing quote"),
            }
        }
    } else {
        let end = input.find(char::is_whitespace).unwrap_or(input.len());
        let raw = &input[..end];
        if raw.contains(['"', '\\']) {
            bail!("Invalid search expression: quotes and escapes require a quoted value");
        }
        value.push_str(raw);
        &input[end..]
    };
    if value.is_empty() {
        bail!("Invalid search expression: values must not be empty");
    }
    Ok((value, remaining))
}

pub(crate) enum Predicate {
    Method { value: String, negated: bool },
    Host { value: Host, negated: bool },
    Status { value: u16, comparison: Comparison },
    Body(String),
    State(State),
    Edited(bool),
}

impl Predicate {
    fn parse(field: &str, operator: &str, value: String) -> Result<Self> {
        match (field, operator) {
            ("method", "=" | "!=") => {
                if !value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
                {
                    bail!("Invalid search expression: method must be an HTTP token");
                }
                Ok(Self::Method {
                    value,
                    negated: operator == "!=",
                })
            }
            ("host", "=" | "!=") => {
                let value = Host::parse(&value).map_err(|_| {
                    anyhow!("Invalid search expression: host must be a hostname without a port")
                })?;
                Ok(Self::Host {
                    value,
                    negated: operator == "!=",
                })
            }
            ("status", "=" | "!=" | ">" | ">=" | "<" | "<=") => {
                let status = value.parse::<u16>().ok().filter(|status| {
                    value.bytes().all(|c| c.is_ascii_digit()) && (100..=599).contains(status)
                });
                let value = status.ok_or_else(|| {
                    anyhow!("Invalid search expression: status must be an integer from 100 to 599")
                })?;
                let comparison = match operator {
                    "=" => Comparison::Equal,
                    "!=" => Comparison::NotEqual,
                    ">" => Comparison::Greater,
                    ">=" => Comparison::GreaterOrEqual,
                    "<" => Comparison::Less,
                    "<=" => Comparison::LessOrEqual,
                    _ => unreachable!(),
                };
                Ok(Self::Status { value, comparison })
            }
            ("body", "~=") => Ok(Self::Body(value.to_lowercase())),
            ("state", "=") => Ok(Self::State(match value.as_str() {
                "pending" => State::Pending,
                "error" => State::Error,
                "complete" => State::Complete,
                _ => bail!("Invalid search expression: state must be pending, error, or complete"),
            })),
            ("edited", "=") => Ok(Self::Edited(match value.as_str() {
                "true" => true,
                "false" => false,
                _ => bail!("Invalid search expression: edited must be true or false"),
            })),
            _ => bail!("Invalid search expression: unsupported field or operator"),
        }
    }

    fn matches(&self, exchange: &Exchange) -> bool {
        match self {
            Self::Method { value, negated } => {
                exchange.method.eq_ignore_ascii_case(value) != *negated
            }
            Self::Host { value, negated } => Url::parse(&exchange.url)
                .ok()
                .and_then(|url| {
                    url.host().map(|host| {
                        let equal = match (host, value) {
                            (Host::Domain(actual), Host::Domain(expected)) => {
                                actual.eq_ignore_ascii_case(expected)
                            }
                            (Host::Ipv4(actual), Host::Ipv4(expected)) => actual == *expected,
                            (Host::Ipv6(actual), Host::Ipv6(expected)) => actual == *expected,
                            _ => false,
                        };
                        equal != *negated
                    })
                })
                .unwrap_or(false),
            Self::Status { value, comparison } => {
                exchange.status.is_some_and(|status| match comparison {
                    Comparison::Equal => status == *value,
                    Comparison::NotEqual => status != *value,
                    Comparison::Greater => status > *value,
                    Comparison::GreaterOrEqual => status >= *value,
                    Comparison::Less => status < *value,
                    Comparison::LessOrEqual => status <= *value,
                })
            }
            Self::Body(needle) => {
                (!exchange.request_body_base64
                    && exchange.request_body.to_lowercase().contains(needle))
                    || (!exchange.response_body_base64
                        && exchange.response_body.to_lowercase().contains(needle))
            }
            Self::State(state) => match state {
                State::Pending => !exchange.completed,
                State::Error => exchange.completed && has_error(exchange),
                State::Complete => exchange.completed && !has_error(exchange),
            },
            Self::Edited(value) => exchange.edited == *value,
        }
    }
}

pub(crate) enum Comparison {
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

pub(crate) enum State {
    Pending,
    Error,
    Complete,
}
