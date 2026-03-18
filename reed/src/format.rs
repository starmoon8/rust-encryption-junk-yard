pub const MAGIC: &[u8; 4] = b"AIX8";

pub const VERSION: u8 = 1;

pub const SALT_LEN: usize = 16;

pub const CHUNK_SIZE: usize = 64 * 1024;

pub const DATA_SHARDS: usize = 4;

pub const PARITY_SHARDS: usize = 2;

pub const HEADER_COPIES: usize = 3;