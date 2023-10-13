use rayon::ThreadPoolBuildError;

#[derive(Debug, thiserror::Error)]
pub enum ZapError {
    #[error("{0}")]
    NotImplemented(String),
    #[error("Generic Error: {0}")]
    Generic(String),
    #[error(transparent)]
    HashingError(#[from] HashingError),
    #[error(transparent)]
    PasswordError(#[from] PasswordError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    CompressionError(#[from] CompressionError),
    #[error(transparent)]
    DecompressionError(#[from] DecompressionError),
    #[error(transparent)]
    EncryptionError(#[from] EncryptionError),
    #[error(transparent)]
    EncryptionSecretError(#[from] EncryptionSecretError),
    #[error(transparent)]
    FailedToInitialiseLogger(#[from] log::SetLoggerError),
}

#[derive(Debug, thiserror::Error)] 
pub enum EncryptionError
{
    #[error(transparent)]
    InitError(EncryptionSecretError)
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptorInitError {
    #[error("Failed to init algorithm: {0}")]
    AlgorithmError(String),
    #[error(transparent)]
    EncryptionSecretError(#[from] EncryptionSecretError)
}

#[derive(Debug, thiserror::Error)] 
pub enum EncryptionSecretError
{
    #[error(transparent)]
    Password(#[from] PasswordError),
    #[error(transparent)]
    Key(#[from] EncryptionKeyError)
}

#[derive(Debug, thiserror::Error)] 
pub enum EncryptionKeyError
{
    #[error("Keyfile not provided")]
    KeyfileNotProvided,
    #[error("Keyfile not found: {0}")]
    FailedToFindKeyfile(String)
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("Passwords do not match")]
    PasswordsDoNotMatch,
    #[error("Password is empty")]
    PasswordEmpty,
    #[error(transparent)]
    HashingError(#[from] HashingError),
    #[error(transparent)]
    InputError(#[from] InputError),
}

#[derive(Debug, thiserror::Error)]
pub enum HashingError {
    #[error("UnrecognisedAlgorithm: {0}")]
    UnrecognisedAlgorithm(String),
    #[error("UnrecognisedAlgorithmLength: {0}")]
    UnrecognisedAlgorithmLength(usize)
}

#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("Failed to get user input: {0}")]
    UserInputFailed(#[from] std::io::Error)
}

#[derive(Debug, thiserror::Error)] 
pub enum CompressionError {
    #[error("Failed to build thread pool: {0}")]
    FailedToBuildThreadPool(#[from] ThreadPoolBuildError),
    #[error("Failed to walk directory: {0}")]
    FailedToWalkDirectory(#[from] walkdir::Error),
    #[error("Failed to compress file: {0}")]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    PathRewriteError(#[from] PathRewriteError)
}

#[derive(Debug, thiserror::Error)]
pub enum PathRewriteError {
    #[error("Failed to convert OsStr to str: {0}")]
    TypeConversionError(String),
    #[error("Failed to get file_name for: {0}")]
    FileNameError(String),

}

#[derive(Debug, thiserror::Error)] 
pub enum DecompressionError {
    #[error("Failed to build thread pool: {0}")]
    FailedToBuildThreadPool(#[from] ThreadPoolBuildError),
    #[error("Failed to walk directory: {0}")]
    FailedToWalkDirectory(#[from] walkdir::Error),
    #[error("Failed to decompress file: {0}")]
    IOError(#[from] std::io::Error)
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineCompressionError {
    #[error("Generic Error: {0}")]
    Generic(String),
    #[error(transparent)]
    HashingError(#[from] HashingError),
    #[error(transparent)]
    PasswordError(#[from] PasswordError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    CompressionError(#[from] CompressionError),
    #[error(transparent)]
    EncryptionError(#[from] EncryptionError),
    #[error(transparent)]
    EncryptionSecretError(#[from] EncryptionSecretError),
    #[error(transparent)]
    EncryptorInitError(#[from] EncryptorInitError),
    #[error(transparent)]
    CompressorInitError(#[from] CompressorInitError),
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineDecompressionError {
    #[error("Generic Error: {0}")]
    Generic(String),
    #[error(transparent)]
    HashingError(HashingError),
    #[error(transparent)]
    PasswordError(PasswordError),
    #[error(transparent)]
    IOError(std::io::Error),
    #[error(transparent)]
    DecompressionError(DecompressionError),
    #[error(transparent)]
    EncryptionError(EncryptionError),
    #[error(transparent)]
    EncryptionSecretError(EncryptionSecretError),
    #[error(transparent)]
    DecryptorInitError(EncryptorInitError),
    #[error(transparent)]
    CompressionInitError(CompressorInitError),
}

impl From<CompressorInitError> for PipelineDecompressionError {
    fn from(value: CompressorInitError) -> Self {
        PipelineDecompressionError::CompressionInitError(value)
    }
}

impl From<EncryptorInitError> for PipelineDecompressionError {
    fn from(value: EncryptorInitError) -> Self {
        PipelineDecompressionError::DecryptorInitError(value)
    }
}

impl From<EncryptionSecretError> for PipelineDecompressionError {
    fn from(value: EncryptionSecretError) -> Self {
        PipelineDecompressionError::EncryptionSecretError(value)
    }
}

impl From<EncryptionError> for PipelineDecompressionError {
    fn from(value: EncryptionError) -> Self {
        PipelineDecompressionError::EncryptionError(value)
    }
}

impl From<DecompressionError> for PipelineDecompressionError {
    fn from(value: DecompressionError) -> Self {
        PipelineDecompressionError::DecompressionError(value)
    }
}

impl From<std::io::Error> for PipelineDecompressionError {
    fn from(value: std::io::Error) -> Self {
        PipelineDecompressionError::IOError(value)
    }
}

impl From<PasswordError> for PipelineDecompressionError {
    fn from(value: PasswordError) -> Self {
        PipelineDecompressionError::PasswordError(value)
    }
}

impl From<HashingError> for PipelineDecompressionError {
    fn from(value: HashingError) -> Self {
        PipelineDecompressionError::HashingError(value)
    }
}

impl From<ThreadPoolBuildError> for PipelineDecompressionError {
    fn from(value: ThreadPoolBuildError) -> Self {
        PipelineDecompressionError::DecompressionError(DecompressionError::FailedToBuildThreadPool(value))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineBuildError {
    #[error(transparent)]
    CompressInit(CompressorInitError),
    #[error(transparent)]
    SignerInit(SignerInitError),
    #[error(transparent)]
    EncryptorInit(EncryptorInitError)
}

impl From<CompressorInitError> for PipelineBuildError {
    fn from(value: CompressorInitError) -> Self {
        PipelineBuildError::CompressInit(value)
    }
}

impl From<SignerInitError> for PipelineBuildError {
    fn from(value: SignerInitError) -> Self {
        PipelineBuildError::SignerInit(value)
    }
}

impl From<EncryptorInitError> for PipelineBuildError {
    fn from(value: EncryptorInitError) -> Self {
        PipelineBuildError::EncryptorInit(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompressorInitError {

}

#[derive(Debug, thiserror::Error)]
pub enum SignerInitError {
    
}