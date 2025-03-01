

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError { // TODO : Rename this error
    #[error("Not yet implemented: {0}")]
    NotYetImplemented(&'static str),
    #[error("File not found: {0}")]
    FileNotFound(String),
}