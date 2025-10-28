#![allow(dead_code)]
#![allow(unused_variables)]
extern crate bincode;
extern crate math;
extern crate serde;
use crate::disk::{BlockDisk, Disk, BLOCK_SIZE};
use math::round;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

const MAGIC_NUMBER: u32 = 0xf0f03410;
const INODES_PER_BLOCK: u32 = 128;
const POINTERS_PER_INODE: u32 = 5;
const POINTERS_PER_BLOCK: u32 = 1024;
const INODE_BLOCKS_FRACTION: f64 = 0.10;
const INODE_SIZE: usize = 32;

#[derive(Debug)]
pub enum FileSystemError {
    DiskWriteFailure,
    DiskReadFailure,
    MiscellaneousFailure,
    InvalidSuperblock,
    NoFreeInodes,
}

pub trait FileSystem<BlockDisk: Disk>
where
    Self: Sized,
{
    fn format(disk: BlockDisk) -> Result<(), FileSystemError>;

    fn mount(disk: BlockDisk) -> Result<Self, FileSystemError>;

    fn create(&mut self) -> Result<usize, FileSystemError>;
    fn remove(&mut self, inumber: usize) -> Result<bool, FileSystemError>;
    fn stat(&self, inumber: usize) -> Result<usize, FileSystemError>;

    fn read(
        &mut self,
        inumber: usize,
        data: &mut Vec<u8>,
        offset: usize,
    ) -> Result<usize, FileSystemError>;
    fn write(
        &mut self,
        inumber: usize,
        data: Vec<u8>,
        offset: usize,
    ) -> Result<usize, FileSystemError>;
}

#[derive(Serialize, Deserialize)]
struct Superblock {
    magic: u32,
    num_blocks: u32,
    num_inode_blocks: u32,
    num_inodes: u32,
}

#[derive(Serialize, Deserialize)]
struct Inode {
    valid: u32,
    size: u32,
    direct: [u32; POINTERS_PER_INODE as usize],
    indirect: u32,
}

pub struct SimpleFileSystem<BlockDisk: Disk> {
    disk: BlockDisk,
    inode_block: Vec<u8>,
    bitmap: Vec<bool>,
}

impl FileSystem<BlockDisk> for SimpleFileSystem<BlockDisk> {
    fn format(mut disk: BlockDisk) -> Result<(), FileSystemError> {
        SimpleFileSystem::clear_disk(&mut disk);

        let num_blocks: u32 = disk.size() as u32;
        let num_inode_blocks: u32 =
            round::ceil(num_blocks as f64 * INODE_BLOCKS_FRACTION, 0) as u32;
        let num_inodes: u32 = (INODES_PER_BLOCK * num_inode_blocks) as u32;

        let superblock: Superblock = Superblock {
            magic: MAGIC_NUMBER,
            num_blocks: num_blocks,
            num_inode_blocks: num_inode_blocks,
            num_inodes: INODES_PER_BLOCK * num_inode_blocks,
        };

        let mut superblock_bytes: Vec<u8> = match bincode::serialize(&superblock) {
            Ok(bytes) => bytes,
            Err(_e) => return Err(FileSystemError::MiscellaneousFailure),
        };

        superblock_bytes.resize(BLOCK_SIZE, 0);

        match disk.write(0, superblock_bytes) {
            Ok(()) => {}
            Err(_e) => return Err(FileSystemError::DiskWriteFailure),
        };

        for i in 1..=num_inode_blocks {
            match disk.write(i as usize, vec![0; BLOCK_SIZE]) {
                Ok(()) => {}
                Err(_e) => return Err(FileSystemError::DiskWriteFailure),
            };
        }

        Ok(())
    }

    fn mount(mut disk: BlockDisk) -> Result<Self, FileSystemError> {
        let first_block: Vec<u8> = match disk.read(0) {
            Ok(bytes) => bytes,
            Err(_e) => return Err(FileSystemError::DiskReadFailure),
        };

        let superblock: Superblock = match bincode::deserialize(&first_block[..]) {
            Ok(block) => block,
            Err(_e) => return Err(FileSystemError::MiscellaneousFailure),
        };

        if superblock.magic != MAGIC_NUMBER {
            return Err(FileSystemError::InvalidSuperblock);
        }

        let inode_block: Vec<u8> = match disk.read(1) {
            Ok(bytes) => bytes,
            Err(_e) => return Err(FileSystemError::DiskReadFailure),
        };

        let bitmap: Vec<bool> = vec![true; disk.size()];

        let mut filesystem: SimpleFileSystem<BlockDisk> = SimpleFileSystem {
            disk: disk,
            inode_block: inode_block,
            bitmap: bitmap,
        };

        let inodes_in_block = (BLOCK_SIZE / INODE_SIZE) as usize;
        for i in 0..inodes_in_block {
            let inode: Inode = match filesystem.get_inode(i) {
                Ok(inode) => inode,
                Err(_) => continue,
            };

            if inode.valid != 0 {
                for j in 0..POINTERS_PER_INODE as usize {
                    let ptr = inode.direct[j];
                    if ptr as usize > 0 && (ptr as usize) < filesystem.disk.size() {
                        filesystem.bitmap[ptr as usize] = false;
                    }
                }
                if inode.indirect != 0 && (inode.indirect as usize) < filesystem.disk.size() {
                    filesystem.bitmap[inode.indirect as usize] = false;
                }
            }
        }

        Ok(filesystem)
    }

    fn create(&mut self) -> Result<usize, FileSystemError> {
        let mut curr_inumber: usize = 0;

        let mut inode_block: Vec<u8> = self.inode_block.clone();

        let inodes_in_block = (BLOCK_SIZE / INODE_SIZE) as usize;
        for inum in 0..inodes_in_block {
            let offset = inum * INODE_SIZE;
            let valid_field_bytes: [u8; 4] = inode_block[offset..offset + 4].try_into().unwrap();

            let valid: bool = SimpleFileSystem::slice_to_u32(&valid_field_bytes) != 0;

            if !valid {
                let val_bytes = 1u32.to_be_bytes();
                inode_block[offset..offset + 4].copy_from_slice(&val_bytes);

                match self.disk.write(1, inode_block.clone()) {
                    Ok(()) => {}
                    Err(_e) => return Err(FileSystemError::DiskWriteFailure),
                };

                self.inode_block = match self.disk.read(1) {
                    Ok(bytes) => bytes,
                    Err(_e) => return Err(FileSystemError::DiskReadFailure),
                };

                return Ok(curr_inumber);
            }

            curr_inumber += 1;
        }

        Err(FileSystemError::NoFreeInodes)
    }

    fn remove(&mut self, inumber: usize) -> Result<bool, FileSystemError> {
        unimplemented!();
    }

    fn stat(&self, inumber: usize) -> Result<usize, FileSystemError> {
        let inode: Inode = self.get_inode(inumber)?;
        Ok(inode.size as usize)
    }

    fn read(
        &mut self,
        inumber: usize,
        data: &mut Vec<u8>,
        offset: usize,
    ) -> Result<usize, FileSystemError> {
        unimplemented!();
    }

    fn write(
        &mut self,
        inumber: usize,
        data: Vec<u8>,
        offset: usize,
    ) -> Result<usize, FileSystemError> {
        unimplemented!();
    }
}

impl SimpleFileSystem<BlockDisk> {
    fn clear_disk(disk: &mut BlockDisk) {
        for i in 0..disk.size() {
            disk.write(i, vec![0; BLOCK_SIZE]).unwrap();
        }
    }

    fn get_inode(&self, inumber: usize) -> Result<Inode, FileSystemError> {
        let inode_block: &Vec<u8> = &self.inode_block;

        let max_inodes = BLOCK_SIZE / INODE_SIZE;
        if inumber >= max_inodes {
            return Err(FileSystemError::MiscellaneousFailure);
        }

        let offset = inumber * INODE_SIZE;

        let valid =
            SimpleFileSystem::slice_to_u32(&inode_block[offset..offset + 4].try_into().unwrap());
        let size = SimpleFileSystem::slice_to_u32(
            &inode_block[offset + 4..offset + 8].try_into().unwrap(),
        );

        let direct0 = SimpleFileSystem::slice_to_u32(
            &inode_block[offset + 8..offset + 12].try_into().unwrap(),
        );
        let direct1 = SimpleFileSystem::slice_to_u32(
            &inode_block[offset + 12..offset + 16].try_into().unwrap(),
        );
        let direct2 = SimpleFileSystem::slice_to_u32(
            &inode_block[offset + 16..offset + 20].try_into().unwrap(),
        );
        let direct3 = SimpleFileSystem::slice_to_u32(
            &inode_block[offset + 20..offset + 24].try_into().unwrap(),
        );
        let direct4 = SimpleFileSystem::slice_to_u32(
            &inode_block[offset + 24..offset + 28].try_into().unwrap(),
        );

        let indirect = SimpleFileSystem::slice_to_u32(
            &inode_block[offset + 28..offset + 32].try_into().unwrap(),
        );

        let inode = Inode {
            valid: valid,
            size: size,
            direct: [direct0, direct1, direct2, direct3, direct4],
            indirect: indirect,
        };

        Ok(inode)
    }

    fn slice_to_u32(bytes: &[u8; 4]) -> u32 {
        ((bytes[0] as u32) << 24)
            | ((bytes[1] as u32) << 16)
            | ((bytes[2] as u32) << 8)
            | bytes[3] as u32
    }
}
