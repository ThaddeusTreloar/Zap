mod compression;
mod encryption;
mod error;
mod logging;
mod password;

use std::{
    fs::{self, File},
    io::BufWriter,
};

use anyhow::Context;
use clap::{Parser, Subcommand};

use log::info;
use zap::{encryption::EncryptionSecret, build_common_extension};

use zapf::{pack_files, unpack_files};

use crate::cli_util::{logging::init_logger, password::get_password_confirm, error::RuntimeError};

use self::{
    compression::{BinCompressionType, CompressionLevel},
    encryption::BinEncryptionType,
    logging::Verbosity,
    password::get_password_noconf,
};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Zap is a simple program to compress/encrypt a folder."
)]

pub struct Args {
    #[command(subcommand)]
    command: Command,
}

impl Args {
    pub fn execute(self) -> Result<(), anyhow::Error> {
        self.command.execute()
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Archive a folder 
    Archive {
        /// Input folder
        input: String,
        #[arg(short, long)]
        /// Output file
        output: Option<String>,
        /// Encrypt using default algorithm (XChaChaPoly1305)
        #[arg(short, long)]
        encrypt: bool,
        /// Compress using default algorithm (Lz4)
        #[arg(short, long)]
        compress: bool,
        /// Path to private key file (not currently supported)
        #[arg(short, long)]
        keypath: Option<String>,
        /// Output verbosity
        #[arg(short, long, default_value = "normal")]
        verbosity: Verbosity,
        /// Override encryption algorithm used
        #[arg(long, default_value = "passthrough")]
        encryption_algorithm: BinEncryptionType,
        /// Override compression algorithm used
        #[arg(long, default_value = "passthrough")]
        compression_algorithm: BinCompressionType,
        /// Compression level when using [--compression_algorithm gzip]
        #[arg(long, default_value = "fastest")]
        compression_level: CompressionLevel,
    },
    /// Extract an archive
    Extract {
        /// Input file
        input: String,
        //#[arg(short, long)]
        /// Output folder
        output: String,
        #[arg(short, long)]
        /// Decrypt using default algorithm (XChaChaPoly1305)
        encrypt: bool,
        #[arg(short, long)]
        /// Decompress using default algorithm (Lz4)
        compress: bool,
        /// Path to private key file (not currently supported)
        #[arg(short, long)]
        keypath: Option<String>,
        /// Output verbosity
        #[arg(short, long, default_value = "normal")]
        verbosity: Verbosity,
        /// Override encryption algorithm used
        #[arg(long, default_value = "passthrough")]
        encryption_algorithm: BinEncryptionType,
        /// Override compression algorithm used
        #[arg(long, default_value = "passthrough")]
        compression_algorithm: BinCompressionType,
    },
    /// List contents of an archive
    List {
        archive: String,
        #[arg(short, long, default_value = "normal")]
        verbosity: Verbosity,
    },
}

impl Command {
    pub fn execute(self) -> Result<(), anyhow::Error> {
        match self {
            Command::Archive {
                input,
                output,
                encrypt: encryption,
                compress: compression,
                keypath,
                verbosity,
                mut encryption_algorithm,
                mut compression_algorithm,
                compression_level,
            } => {
                if let (true, BinEncryptionType::Passthrough) = (encryption, &encryption_algorithm) {
                    encryption_algorithm = BinEncryptionType::XChaCha;
                }

                if let (true, BinCompressionType::Passthrough) = (compression, &compression_algorithm) {
                    compression_algorithm = BinCompressionType::Lz4;
                }

                Self::archive(
                    input,
                    output,
                    keypath,
                    verbosity,
                    encryption_algorithm,
                    compression_algorithm,
                    compression_level,
                )
            },
            Command::Extract {
                input,
                output,
                encrypt: encryption,
                compress: compression,
                keypath,
                verbosity,
                mut encryption_algorithm,
                mut compression_algorithm,
            } => {
                if let (true, BinEncryptionType::Passthrough) = (encryption, &encryption_algorithm) {
                    encryption_algorithm = BinEncryptionType::XChaCha;
                }

                if let (true, BinCompressionType::Passthrough) = (compression, &compression_algorithm) {
                    compression_algorithm = BinCompressionType::Lz4;
                }
                Self::extract(
                    input,
                    output,
                    keypath,
                    verbosity,
                    encryption_algorithm,
                    compression_algorithm,
                )
            },
            Command::List { archive, verbosity } => Self::list(archive, verbosity),
        }
    }

    fn archive(
        input: String,
        output: Option<String>,
        keypath: Option<String>,
        verbosity: Verbosity,
        encryption_algorithm: BinEncryptionType,
        compression_algorithm: BinCompressionType,
        compression_level: CompressionLevel,
    ) -> Result<(), anyhow::Error> {
        preamble(verbosity).context("Running preamble.")?;

        let encryption_secret: EncryptionSecret = match (&encryption_algorithm, keypath) {
            (BinEncryptionType::Passthrough, _) => EncryptionSecret::None,
            (_, Some(path)) => EncryptionSecret::Key(path),
            (_, None) => EncryptionSecret::Password(match get_password_confirm(256) {
                Ok(pass) => pass,
                Err(e) => return Err(e.into()),
            }),
        };

        // TODO : Remove these clones
        let mut out_extension = build_common_extension(&encryption_algorithm.clone().into(), &compression_algorithm.clone().into());
        out_extension.push_str(".zap");

        zap::compress_directory(
            &input,
            "/tmp/unpacked",
            encryption_algorithm.into(),
            encryption_secret,
            compression_algorithm.into(),
            compression_level.into(),
            zap::signing::SigningType::default(),
        ).context("Compressing directory.")?;

        let out_name = format!("{}{}", input.trim_end_matches('.'), out_extension);

        let out_file = File::create(out_name).context("Creating output file")?;

        let mut out_writer = BufWriter::new(out_file);

        pack_files("/tmp/unpacked", &mut out_writer).context("Packing files")?;

        fs::remove_dir_all("/tmp/unpacked").context("Cleaning up...")
    }

    fn extract(
        input: String,
        output: String,
        keypath: Option<String>,
        verbosity: Verbosity,
        encryption_algorithm: BinEncryptionType,
        compression_algorithm: BinCompressionType,
    ) -> Result<(), anyhow::Error> {
        preamble(verbosity).context("Running preamble")?;

        let encryption_secret: EncryptionSecret = match (&encryption_algorithm, keypath) {
            (BinEncryptionType::Passthrough, _) => EncryptionSecret::None,
            (_, None) => EncryptionSecret::Password(match get_password_noconf(256) {
                Ok(pass) => pass,
                Err(e) => return Err(e.into()),
            }),
            (_, Some(path)) => EncryptionSecret::Key(path),
        };

        // Need to check if this function validates path names
        // to prevent directory traversal.
        unpack_files(input, "/tmp/unpacked").context("Unpacking files.")?;

        zap::decompress_directory(
            "/tmp/unpacked",
            &output,
            encryption_algorithm.into(),
            encryption_secret,
            compression_algorithm.into(),
            zap::signing::SigningType::default(),
        ).context("Decompressing directory.")?;

        fs::remove_dir_all("/tmp/unpacked").context("Cleaning up.")
    }

    fn list(archive: String, verbosity: Verbosity) -> Result<(), anyhow::Error> {
        preamble(verbosity).context("Running preamble")?;

        info!("Listing archive: {}", archive);

        Err(RuntimeError::NotYetImplemented("Listing archives").into())
    }
}

fn preamble(verbosity: Verbosity) -> Result<(), anyhow::Error> {
    init_logger(verbosity).context("Initialising logger")?;

    log::debug!("pid: {}", std::process::id());

    Ok(())
}
