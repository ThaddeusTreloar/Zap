use zap::signing::SigningType;

use super::{encryption::BinEncryptionType, compression::BinCompressionType};



pub fn parse_extensions() -> (BinEncryptionType, BinCompressionType, SigningType) {
    (BinEncryptionType::Passthrough, BinCompressionType::Passthrough, SigningType::Passthrough)
}