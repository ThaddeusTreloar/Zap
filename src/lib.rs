pub mod compression;
pub mod encryption;
pub mod error;
pub mod internal;
pub mod pipeline;
pub mod prelude;
pub mod signing;

use core::panic;
use std::{
    backtrace,
    path::{self, Path, PathBuf},
    sync::Arc,
};

use crate::pipeline::ProcessingPipeline;
use compression::CompressionType;
use crossbeam::sync::WaitGroup;
use encryption::{EncryptionSecret, EncryptionType};
use error::{CompressionError, DecompressionError, PathRewriteError};
use log::{debug, error, info};
use rayon::{ThreadPoolBuilder, prelude::{IntoParallelRefIterator, IntoParallelIterator}, prelude::ParallelIterator};
use signing::SigningType;
use walkdir::WalkDir;

pub struct Processor {}

pub fn build_common_extension(enc: &EncryptionType, comp: &CompressionType) -> String {
    let mut ext = String::new();

    match enc {
        EncryptionType::Passthrough => (),
        EncryptionType::XChaCha => ext.push_str(".xcha"),
        EncryptionType::AesGcm => ext.push_str(".aes"),
        EncryptionType::ChaCha => ext.push_str(".cha"),
    }

    match comp {
        CompressionType::Passthrough => (),
        CompressionType::Lz4 => ext.push_str(".lz4"),
        CompressionType::Gzip => ext.push_str(".gz"),
        CompressionType::Snappy => ext.push_str(".sz"),
    }
    
    ext
}

fn rewrite_ext(path: &Path, extension: &str) -> Result<PathBuf, CompressionError> {
    match path.extension() {
        Some(ext) => {
            let base = match ext.to_str() {
                Some(b) => b,
                None => return Err(PathRewriteError::TypeConversionError("Failed to convert extension to string".into()).into()),
            };

            debug!("Base: {:?}", base);
            debug!("Extension: {:?}", extension);

            Ok(path.with_extension(format!("{}{}", base, extension)))
        },
        None => Ok(path.with_extension(extension.trim_start_matches('.'))),
    }
}

fn clear_ext(path: &Path) -> Result<PathBuf, CompressionError> {
    let input_file_path: PathBuf = path.to_path_buf();

    let mut input_file_extensions: Vec<&str> = match input_file_path
        .file_name() {
            Some(ext) => ext.to_str()
                .expect("Unable to convert extension to string.")
                .split('.')
                .rev().collect(),
            None => return Err(PathRewriteError::FileNameError("Failed to get file name".into()).into()),
        };

    input_file_extensions
        .retain(|ext| !["xcha", "aes", "cha", "lz4", "gz", "sz"].contains(ext));

    input_file_extensions.reverse();

    debug!("Input file extensions: {:?}", input_file_extensions);

    Ok(input_file_path
        .parent()
        .expect("UNable to get parent directory.")
        .join(
            input_file_extensions
                .join(".")
        ))
}

fn get_types_from_extensions(path: &Path) -> Result<(EncryptionType, CompressionType), CompressionError> {
    let input_file_path: PathBuf = path.to_path_buf();

    let mut input_file_extensions: Vec<&str> = match input_file_path
        .file_name() {
            Some(ext) => ext.to_str()
                .expect("Unable to convert extension to string.")
                .split('.')
                .rev().collect(),
            None => return Err(PathRewriteError::FileNameError("Failed to get file name".into()).into()),
        };

    let mut encryption_algorithm: EncryptionType = EncryptionType::Passthrough;
    let mut compression_algorithm: CompressionType = CompressionType::Passthrough;

    for ext in input_file_extensions.iter() {
        match *ext {
            "xcha" => encryption_algorithm = EncryptionType::XChaCha,
            "aes" => encryption_algorithm = EncryptionType::AesGcm,
            "cha" => encryption_algorithm = EncryptionType::ChaCha,
            "lz4" => compression_algorithm = CompressionType::Lz4,
            "gz" => compression_algorithm = CompressionType::Gzip,
            "sz" => compression_algorithm = CompressionType::Snappy,
            _ => (),
        }
    }

    Ok((encryption_algorithm, compression_algorithm))
}

pub fn compress_directory(
    input_folder_path: &str,
    output_folder_path: &str,
    encryption: EncryptionType,
    encryption_secret: EncryptionSecret,
    compression: CompressionType,
    compression_level: flate2::Compression,
    signing: SigningType,
) -> Result<(), CompressionError> {

    info!("Compressing directory: {:?} -> {:?}", input_folder_path, output_folder_path);
    info!("Encryption: {:?}", encryption);
    info!("Compression: {:?}", compression);
    info!("Compression level: {:?}", compression_level);
    info!("Signing: {:?}", signing);

    let common_extension = build_common_extension(&encryption, &compression);

    let input_paths: Vec<PathBuf> = WalkDir::new(input_folder_path)
        .into_iter()
        .map(|e| e.unwrap_or_else(|e| panic!("Error: {:?}", e)))
        .map(|e| e.into_path())
        // TODO : Explore allow follow symlnks option
        .filter(|e|e.is_file())
        .collect();

    let output_paths: Vec<PathBuf> = input_paths
        .iter()
        .filter_map(|e| match e.strip_prefix(input_folder_path) {
            Ok(p) => rewrite_ext(p, &common_extension).ok(),
            Err(e) => {
                panic!("Error: {:?}", e);
                // None
            }
        })
        .map(
            |p| Path::new(output_folder_path).join(p)
        ).collect();

    let jobs: Vec<(PathBuf, PathBuf)> = input_paths
        .into_iter()
        .zip(output_paths)
        .collect();

    jobs.iter().for_each(
        |(input, output)| debug!(
            "Compressing: {:?} -> {:?}",
            input.display(),
            output.display()
        )
    );

    jobs.par_iter()
        .map(
            |(_, output)| output.parent().unwrap()
        )
        .for_each(
        |parent| 
            std::fs::create_dir_all(parent)
                .expect("Failed to create all the required directories/subdirectories")
        );
    
    jobs.into_par_iter()
        .for_each(
            |(input, output)| {
                let pipeline = ProcessingPipeline::builder()
                    .with_source(input.clone())
                    .with_destination(output)
                    .with_compression(&compression)
                    .with_compression_level(&compression_level)
                    .with_encryption(&encryption)
                    .with_encryption_secret(&encryption_secret)
                    .with_signing(&signing)
                    .build();

                    match pipeline.compress_dir() {
                        Ok(_) => debug!(
                            "Finished compressing '{:?}' successfully",
                            input.display()
                        ),
                        Err(e) => {
                            
                            let bt = backtrace::Backtrace::capture();
            
                            error!(
                                "Error while compressing '{}': {:?}",
                                input.display(),
                                e
                            );
                            log::trace!(
                                "Error while compressing '{}': {:?}",
                                input.display(),
                                bt
                            );
            
                            error!("Error compressing file {:?}", e);
                            panic!();
        }}});

    Ok(())
}

// todo: This function will alter the filename of binary files eg:
// a binary called 'someBinary' will end up as 'someBinary.'
pub fn decompress_directory(
    input_folder_path: &str,
    output_folder_path: &str,
    encryption: EncryptionType,
    encryption_secret: EncryptionSecret,
    compression: CompressionType,
    signing: SigningType,
) -> Result<(), DecompressionError> {
    
    info!("Decompressing directory: {:?} -> {:?}", input_folder_path, output_folder_path);
    info!("Encryption: {:?}", encryption);
    info!("Compression: {:?}", compression);
    info!("Signing: {:?}", signing);

    let input_paths: Vec<PathBuf> = WalkDir::new(input_folder_path)
        .into_iter()
        .map(|e| e.unwrap_or_else(|e| panic!("Error: {:?}", e)))
        .map(|e| e.into_path())
        // TODO : Explore allow follow symlnks option
        .filter(|e|e.is_file())
        .collect();

    let output_paths: Vec<PathBuf> = input_paths
        .iter()
        .filter_map(|e| match e.strip_prefix(input_folder_path) {
            Ok(p) => self::clear_ext(p).ok(),
            Err(e) => {
                panic!("Error: {:?}", e);
                // None
            }
        })
        .map(
            |p| Path::new(output_folder_path).join(p)
        ).collect();

    let jobs: Vec<(PathBuf, PathBuf)> = input_paths
        .into_iter()
        .zip(output_paths)
        .collect();

    jobs.iter().for_each(
        |(input, output)| debug!(
            "Compressing: {:?} -> {:?}",
            input.display(),
            output.display()
        )
    );

    jobs.par_iter()
        .map(
            |(_, output)| output.parent().unwrap()
        )
        .for_each(
        |parent| 
            std::fs::create_dir_all(parent)
                .expect("Failed to create all the required directories/subdirectories")
        );

    let _compression_level = flate2::Compression::default(); // Needs to be deleted at some point
    
    jobs.into_par_iter()
        .for_each(
            |(input, output)| {
                let pipeline = ProcessingPipeline::builder()
                    .with_source(input.clone())
                    .with_destination(output)
                    .with_compression(&compression)
                    .with_compression_level(&_compression_level) // TODO: Make compression level optional
                    .with_encryption(&encryption)
                    .with_encryption_secret(&encryption_secret)
                    .with_signing(&signing)
                    .build();

                    match pipeline.decompress_dir() {
                        Ok(_) => debug!(
                            "Finished compressing '{:?}' successfully",
                            input.display()
                        ),
                        Err(e) => {
                            
                            let bt = backtrace::Backtrace::capture();
            
                            error!(
                                "Error while compressing '{}': {:?}",
                                input.display(),
                                e
                            );
                            log::trace!(
                                "Error while compressing '{}': {:?}",
                                input.display(),
                                bt
                            );
            
                            error!("Error compressing file {:?}", e);
                            panic!();
        }}});

    Ok(())
}

