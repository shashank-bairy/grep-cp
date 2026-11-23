use thiserror::Error;

/// Errors surfaced to MCP callers. Every variant renders as a human-readable message that tells the
/// caller what to change; none of them leak filesystem paths outside the configured root.
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("unknown service '{name}'{}", suggestion_suffix(.suggestion))]
    UnknownService {
        name: String,
        suggestion: Option<String>,
    },

    #[error("service '{0}' is not readable by the server user")]
    ServiceUnreadable(String),

    #[error("unknown file '{file}' in service '{service}'; use list_files to get valid names")]
    UnknownFile { service: String, file: String },

    #[error("{0}")]
    WindowRejected(String),

    #[error(
        "plan too large: {files} files / {bytes} bytes selected, limit is {limit} bytes. \
         Narrow the time window, restrict hosts, or use count_matches first"
    )]
    PlanTooLarge {
        files: usize,
        bytes: u64,
        limit: u64,
    },

    #[error("server busy: {0} concurrent requests already running; retry shortly")]
    Busy(usize),

    #[error("{0}")]
    Stopped(String),

    #[error("invalid pattern: {0}")]
    Pattern(String),

    #[error("internal error: {0}")]
    Internal(String),
}

fn suggestion_suffix(s: &Option<String>) -> String {
    match s {
        Some(s) => format!("; did you mean '{s}'?"),
        None => "; use list_services to see available services".to_string(),
    }
}

impl From<std::io::Error> for ToolError {
    fn from(e: std::io::Error) -> Self {
        ToolError::Internal(e.to_string())
    }
}

pub type ToolResult<T> = Result<T, ToolError>;
