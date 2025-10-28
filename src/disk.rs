use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

#[derive(Debug)]
pub enum DiskError {
    ImageOpenFailure,
    ImageReadFailure,
    ImageWriteFailure,
}

pub const BLOCK_SIZE: usize = 4096;

pub trait Disk
where
    Self: Sized,
{
    fn open(path: String, num_blocks: usize) -> Result<Self, DiskError>;

    fn size(&self) -> usize;

    fn mounted(&self) -> bool;
    fn mount(&mut self) -> Result<(), DiskError>;
    fn unmount(&mut self) -> Result<(), DiskError>;

    fn read(&mut self, block_number: usize) -> Result<Vec<u8>, DiskError>;
    fn write(&mut self, block_number: usize, data: Vec<u8>) -> Result<(), DiskError>;
}

#[derive(Debug)]
pub struct BlockDisk {
    file_handle: File,
    num_blocks: usize,
    num_reads: u128,
    num_writes: u128,
    mounted: bool,
    num_mounts: u128,
}

impl BlockDisk {
    pub fn try_clone(&self) -> std::io::Result<BlockDisk> {
        Ok(BlockDisk {
            file_handle: self.file_handle.try_clone()?,
            num_blocks: self.num_blocks,
            num_reads: self.num_reads,
            num_writes: self.num_writes,
            mounted: self.mounted,
            num_mounts: self.num_mounts,
        })
    }
}

impl Disk for BlockDisk {
    fn open(path: String, num_blocks: usize) -> Result<Self, DiskError> {
        let file: File = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
        {
            Ok(f) => f,
            Err(_e) => return Err(DiskError::ImageOpenFailure),
        };

        Ok(BlockDisk {
            file_handle: file,
            num_blocks,
            num_reads: 0,
            num_writes: 0,
            mounted: false,
            num_mounts: 0,
        })
    }

    fn size(&self) -> usize {
        self.num_blocks
    }

    fn mounted(&self) -> bool {
        self.mounted
    }

    fn mount(&mut self) -> Result<(), DiskError> {
        self.num_mounts += 1;
        self.mounted = true;
        Ok(())
    }

    fn unmount(&mut self) -> Result<(), DiskError> {
        self.mounted = false;
        Ok(())
    }

    fn read(&mut self, block_number: usize) -> Result<Vec<u8>, DiskError> {
        if self
            .file_handle
            .seek(SeekFrom::Start((block_number * BLOCK_SIZE) as u64))
            .is_err()
        {
            return Err(DiskError::ImageReadFailure);
        }

        let mut data: Vec<u8> = vec![0; BLOCK_SIZE];
        if self.file_handle.read(&mut data).is_err() {
            return Err(DiskError::ImageReadFailure);
        }

        self.num_reads += 1;
        Ok(data)
    }

    fn write(&mut self, block_number: usize, data: Vec<u8>) -> Result<(), DiskError> {
        if self
            .file_handle
            .seek(SeekFrom::Start((block_number * BLOCK_SIZE) as u64))
            .is_err()
        {
            return Err(DiskError::ImageReadFailure);
        }

        let mut write_data = data.clone();
        write_data.truncate(BLOCK_SIZE);
        write_data.resize(BLOCK_SIZE, 0);

        if self.file_handle.write_all(&write_data).is_err() {
            return Err(DiskError::ImageWriteFailure);
        }

        self.num_writes += 1;
        Ok(())
    }
}
