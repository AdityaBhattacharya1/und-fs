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
const DIR_NAME_LEN: usize = 28;
const DIR_ENTRY_SIZE: usize = DIR_NAME_LEN + 4; // name + inumber

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
    superblock: Superblock,
    inode_block: Vec<u8>,
    dir_block: Vec<u8>,
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

        // initialize inode blocks
        for i in 1..=num_inode_blocks {
            match disk.write(i as usize, vec![0; BLOCK_SIZE]) {
                Ok(()) => {}
                Err(_e) => return Err(FileSystemError::DiskWriteFailure),
            };
        }

        // initialize a single directory block right after inode blocks
        let dir_index = 1 + num_inode_blocks as usize;
        match disk.write(dir_index, vec![0; BLOCK_SIZE]) {
            Ok(()) => {}
            Err(_e) => return Err(FileSystemError::DiskWriteFailure),
        };

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

        // read first inode block
        let inode_block: Vec<u8> = match disk.read(1) {
            Ok(bytes) => bytes,
            Err(_e) => return Err(FileSystemError::DiskReadFailure),
        };

        // read directory block after inode blocks
        let dir_index = 1 + superblock.num_inode_blocks as usize;
        let dir_block: Vec<u8> = match disk.read(dir_index) {
            Ok(bytes) => bytes,
            Err(_e) => return Err(FileSystemError::DiskReadFailure),
        };

        let bitmap: Vec<bool> = vec![true; disk.size()];

        let mut filesystem: SimpleFileSystem<BlockDisk> = SimpleFileSystem {
            disk: disk,
            superblock: superblock,
            inode_block: inode_block,
            dir_block: dir_block,
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

        // mark superblock, inode blocks and dir block as used
        filesystem.bitmap[0] = false;
        for i in 1..=filesystem.superblock.num_inode_blocks as usize {
            if i < filesystem.bitmap.len() {
                filesystem.bitmap[i] = false;
            }
        }
        if dir_index < filesystem.bitmap.len() {
            filesystem.bitmap[dir_index] = false;
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
        // read inode
        let mut inode = self.get_inode(inumber)?;
        if inode.valid == 0 {
            return Err(FileSystemError::MiscellaneousFailure);
        }

        // free direct blocks
        for j in 0..POINTERS_PER_INODE as usize {
            let ptr = inode.direct[j] as usize;
            if ptr != 0 && ptr < self.disk.size() {
                self.free_block(ptr)?;
                inode.direct[j] = 0;
            }
        }

        // free indirect block if present
        if inode.indirect != 0 {
            let indirect_block = self
                .disk
                .read(inode.indirect as usize)
                .map_err(|_| FileSystemError::DiskReadFailure)?;
            // each pointer is 4 bytes
            for i in 0..POINTERS_PER_BLOCK as usize {
                let off = i * 4;
                if off + 4 > indirect_block.len() {
                    break;
                }
                let ptr = SimpleFileSystem::<BlockDisk>::slice_to_u32(
                    &indirect_block[off..off + 4].try_into().unwrap(),
                ) as usize;
                if ptr != 0 {
                    self.free_block(ptr)?;
                }
            }
            // free the indirect block itself
            self.free_block(inode.indirect as usize)?;
            inode.indirect = 0;
        }

        // mark inode invalid
        inode.valid = 0;
        inode.size = 0;
        self.write_inode(inumber, &inode)?;

        Ok(true)
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
        let inode = self.get_inode(inumber)?;
        if inode.valid == 0 {
            return Err(FileSystemError::MiscellaneousFailure);
        }

        let file_size = inode.size as usize;
        if offset >= file_size {
            return Ok(0);
        }

        let mut remaining = file_size - offset;
        let mut bytes_read = 0usize;
        let mut logical = offset / BLOCK_SIZE;
        let mut inner_offset = offset % BLOCK_SIZE;

        while remaining > 0 {
            // determine block number for this logical block
            let blockno: usize;
            if logical < POINTERS_PER_INODE as usize {
                blockno = inode.direct[logical] as usize;
            } else {
                if inode.indirect == 0 {
                    break;
                }
                let indirect_block = self
                    .disk
                    .read(inode.indirect as usize)
                    .map_err(|_| FileSystemError::DiskReadFailure)?;
                let idx = logical - POINTERS_PER_INODE as usize;
                let off = idx * 4;
                if off + 4 > indirect_block.len() {
                    break;
                }
                blockno = SimpleFileSystem::<BlockDisk>::slice_to_u32(
                    &indirect_block[off..off + 4].try_into().unwrap(),
                ) as usize;
            }

            if blockno == 0 {
                break;
            }

            let block = self
                .disk
                .read(blockno)
                .map_err(|_| FileSystemError::DiskReadFailure)?;
            let take = std::cmp::min(remaining, BLOCK_SIZE - inner_offset);
            data.extend_from_slice(&block[inner_offset..inner_offset + take]);
            bytes_read += take;
            remaining -= take;
            logical += 1;
            inner_offset = 0;
        }

        Ok(bytes_read)
    }

    fn write(
        &mut self,
        inumber: usize,
        data: Vec<u8>,
        offset: usize,
    ) -> Result<usize, FileSystemError> {
        let mut inode = self.get_inode(inumber)?;
        if inode.valid == 0 {
            return Err(FileSystemError::MiscellaneousFailure);
        }

        let mut bytes_written: usize = 0;
        let mut remaining = data.len();
        let mut src_offset = 0usize;
        let mut cur_offset = offset;

        // write into direct blocks
        for j in 0..POINTERS_PER_INODE as usize {
            if remaining == 0 {
                break;
            }
            // allocate block if needed
            if inode.direct[j] == 0 {
                let b = self.allocate_block()? as u32;
                inode.direct[j] = b;
            }
            let blockno = inode.direct[j] as usize;
            let mut block = self
                .disk
                .read(blockno)
                .map_err(|_| FileSystemError::DiskReadFailure)?;

            let start_in_block = cur_offset % BLOCK_SIZE;
            let take = std::cmp::min(remaining, BLOCK_SIZE - start_in_block);
            block[start_in_block..start_in_block + take]
                .copy_from_slice(&data[src_offset..src_offset + take]);
            self.disk
                .write(blockno, block)
                .map_err(|_| FileSystemError::DiskWriteFailure)?;

            remaining -= take;
            src_offset += take;
            bytes_written += take;
            cur_offset += take;
        }

        // write into indirect blocks
        if remaining > 0 {
            if inode.indirect == 0 {
                let ib = self.allocate_block()? as u32;
                inode.indirect = ib;
                // initialize indirect block with zeros
                self.disk
                    .write(ib as usize, vec![0; BLOCK_SIZE])
                    .map_err(|_| FileSystemError::DiskWriteFailure)?;
            }

            let mut indirect_block = self
                .disk
                .read(inode.indirect as usize)
                .map_err(|_| FileSystemError::DiskReadFailure)?;
            for i in 0..POINTERS_PER_BLOCK as usize {
                if remaining == 0 {
                    break;
                }
                let off = i * 4;
                let ptr = SimpleFileSystem::<BlockDisk>::slice_to_u32(
                    &indirect_block[off..off + 4].try_into().unwrap(),
                ) as usize;
                let blockno = if ptr == 0 {
                    let b = self.allocate_block()?;
                    // write pointer into indirect block
                    let bytes = (b as u32).to_be_bytes();
                    indirect_block[off..off + 4].copy_from_slice(&bytes);
                    b
                } else {
                    ptr
                };

                let mut block = self
                    .disk
                    .read(blockno)
                    .map_err(|_| FileSystemError::DiskReadFailure)?;
                let start_in_block = cur_offset % BLOCK_SIZE;
                let take = std::cmp::min(remaining, BLOCK_SIZE - start_in_block);
                block[start_in_block..start_in_block + take]
                    .copy_from_slice(&data[src_offset..src_offset + take]);
                self.disk
                    .write(blockno, block)
                    .map_err(|_| FileSystemError::DiskWriteFailure)?;

                remaining -= take;
                src_offset += take;
                bytes_written += take;
                cur_offset += take;
            }

            // write back indirect block
            self.disk
                .write(inode.indirect as usize, indirect_block)
                .map_err(|_| FileSystemError::DiskWriteFailure)?;
        }

        // update inode size
        let new_size = std::cmp::max(inode.size as usize, offset + bytes_written) as u32;
        inode.size = new_size;
        self.write_inode(inumber, &inode)?;

        Ok(bytes_written)
    }
}

impl SimpleFileSystem<BlockDisk> {
    fn clear_disk(disk: &mut BlockDisk) {
        for i in 0..disk.size() {
            disk.write(i, vec![0; BLOCK_SIZE]).unwrap();
        }
    }

    fn allocate_block(&mut self) -> Result<usize, FileSystemError> {
        for i in 0..self.bitmap.len() {
            if self.bitmap[i] {
                self.bitmap[i] = false;
                // zero the block on disk
                self.disk
                    .write(i, vec![0; BLOCK_SIZE])
                    .map_err(|_| FileSystemError::DiskWriteFailure)?;
                return Ok(i);
            }
        }
        Err(FileSystemError::MiscellaneousFailure)
    }

    fn free_block(&mut self, blockno: usize) -> Result<(), FileSystemError> {
        if blockno >= self.bitmap.len() {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        self.bitmap[blockno] = true;
        self.disk
            .write(blockno, vec![0; BLOCK_SIZE])
            .map_err(|_| FileSystemError::DiskWriteFailure)?;
        Ok(())
    }

    fn write_inode(&mut self, inumber: usize, inode: &Inode) -> Result<(), FileSystemError> {
        let mut block = self.inode_block.clone();
        let offset = inumber * INODE_SIZE;
        if offset + INODE_SIZE > block.len() {
            return Err(FileSystemError::MiscellaneousFailure);
        }

        block[offset..offset + 4].copy_from_slice(&inode.valid.to_be_bytes());
        block[offset + 4..offset + 8].copy_from_slice(&inode.size.to_be_bytes());
        for j in 0..POINTERS_PER_INODE as usize {
            block[offset + 8 + j * 4..offset + 12 + j * 4]
                .copy_from_slice(&inode.direct[j].to_be_bytes());
        }
        block[offset + 28..offset + 32].copy_from_slice(&inode.indirect.to_be_bytes());

        self.disk
            .write(1, block.clone())
            .map_err(|_| FileSystemError::DiskWriteFailure)?;
        self.inode_block = self
            .disk
            .read(1)
            .map_err(|_| FileSystemError::DiskReadFailure)?;
        Ok(())
    }

    // Directory helpers: fixed-size entries in dir_block
    fn lookup_dir(&self, name: &str) -> Option<usize> {
        let entries = BLOCK_SIZE / DIR_ENTRY_SIZE;
        for i in 0..entries {
            let off = i * DIR_ENTRY_SIZE;
            let name_bytes = &self.dir_block[off..off + DIR_NAME_LEN];
            // find null terminator
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(DIR_NAME_LEN);
            if end == 0 {
                continue;
            }
            let entry_name = match std::str::from_utf8(&name_bytes[..end]) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if entry_name == name {
                let inum_bytes: [u8; 4] = self.dir_block[off + DIR_NAME_LEN..off + DIR_ENTRY_SIZE]
                    .try_into()
                    .unwrap();
                let inum = SimpleFileSystem::<BlockDisk>::slice_to_u32(&inum_bytes) as usize;
                return Some(inum);
            }
        }
        None
    }

    fn add_dir(&mut self, name: &str, inumber: usize) -> Result<(), FileSystemError> {
        if name.len() > DIR_NAME_LEN {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        let entries = BLOCK_SIZE / DIR_ENTRY_SIZE;
        for i in 0..entries {
            let off = i * DIR_ENTRY_SIZE;
            let name_bytes = &self.dir_block[off..off + DIR_NAME_LEN];
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(DIR_NAME_LEN);
            if end == 0 {
                // free slot
                // write name
                let mut new_block = self.dir_block.clone();
                for (j, &b) in name.as_bytes().iter().enumerate() {
                    new_block[off + j] = b;
                }
                // null terminate rest
                if name.len() < DIR_NAME_LEN {
                    new_block[off + name.len()] = 0;
                }
                // write inumber
                new_block[off + DIR_NAME_LEN..off + DIR_ENTRY_SIZE]
                    .copy_from_slice(&(inumber as u32).to_be_bytes());
                self.disk
                    .write(
                        1 + self.superblock.num_inode_blocks as usize,
                        new_block.clone(),
                    )
                    .map_err(|_| FileSystemError::DiskWriteFailure)?;
                self.dir_block = self
                    .disk
                    .read(1 + self.superblock.num_inode_blocks as usize)
                    .map_err(|_| FileSystemError::DiskReadFailure)?;
                return Ok(());
            }
        }
        Err(FileSystemError::MiscellaneousFailure)
    }

    fn remove_dir(&mut self, name: &str) -> Result<bool, FileSystemError> {
        let entries = BLOCK_SIZE / DIR_ENTRY_SIZE;
        for i in 0..entries {
            let off = i * DIR_ENTRY_SIZE;
            let name_bytes = &self.dir_block[off..off + DIR_NAME_LEN];
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(DIR_NAME_LEN);
            if end == 0 {
                continue;
            }
            let entry_name = match std::str::from_utf8(&name_bytes[..end]) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if entry_name == name {
                // clear the entry
                let mut new_block = self.dir_block.clone();
                for k in 0..DIR_ENTRY_SIZE {
                    new_block[off + k] = 0;
                }
                self.disk
                    .write(
                        1 + self.superblock.num_inode_blocks as usize,
                        new_block.clone(),
                    )
                    .map_err(|_| FileSystemError::DiskWriteFailure)?;
                self.dir_block = self
                    .disk
                    .read(1 + self.superblock.num_inode_blocks as usize)
                    .map_err(|_| FileSystemError::DiskReadFailure)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    // high-level named APIs
    pub fn create_named(&mut self, name: &str) -> Result<usize, FileSystemError> {
        if self.lookup_dir(name).is_some() {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        let inum = self.create()?;
        self.add_dir(name, inum)?;
        Ok(inum)
    }

    pub fn remove_named(&mut self, name: &str) -> Result<bool, FileSystemError> {
        if let Some(inum) = self.lookup_dir(name) {
            self.remove(inum)?;
            let _ = self.remove_dir(name)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn read_named(
        &mut self,
        name: &str,
        data: &mut Vec<u8>,
        offset: usize,
    ) -> Result<usize, FileSystemError> {
        if let Some(inum) = self.lookup_dir(name) {
            self.read(inum, data, offset)
        } else {
            Err(FileSystemError::MiscellaneousFailure)
        }
    }

    pub fn write_named(
        &mut self,
        name: &str,
        data: Vec<u8>,
        offset: usize,
    ) -> Result<usize, FileSystemError> {
        if let Some(inum) = self.lookup_dir(name) {
            self.write(inum, data, offset)
        } else {
            Err(FileSystemError::MiscellaneousFailure)
        }
    }

    pub fn list_files(&mut self) -> Result<Vec<(String, usize, Vec<u8>)>, FileSystemError> {
        let mut results: Vec<(String, usize, Vec<u8>)> = Vec::new();
        let entries = BLOCK_SIZE / DIR_ENTRY_SIZE;
        for i in 0..entries {
            let off = i * DIR_ENTRY_SIZE;
            let name_bytes = &self.dir_block[off..off + DIR_NAME_LEN];
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(DIR_NAME_LEN);
            if end == 0 {
                continue;
            }
            let entry_name = match std::str::from_utf8(&name_bytes[..end]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            let inum_bytes: [u8; 4] = self.dir_block[off + DIR_NAME_LEN..off + DIR_ENTRY_SIZE]
                .try_into()
                .unwrap();
            let inum = SimpleFileSystem::<BlockDisk>::slice_to_u32(&inum_bytes) as usize;
            let mut data: Vec<u8> = Vec::new();
            let _ = self.read(inum, &mut data, 0);
            results.push((entry_name, inum, data));
        }
        Ok(results)
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
