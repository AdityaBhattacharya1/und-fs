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
const DIR_NAME_LEN: usize = 20;
const DIR_EXT_LEN: usize = 8;
const DIR_ENTRY_SIZE: usize = 64;

#[derive(Debug)]
pub enum FileSystemError {
    DiskWriteFailure,
    DiskReadFailure,
    MiscellaneousFailure,
    PermissionDenied,
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

        for i in 1..=num_inode_blocks {
            match disk.write(i as usize, vec![0; BLOCK_SIZE]) {
                Ok(()) => {}
                Err(_e) => return Err(FileSystemError::DiskWriteFailure),
            };
        }

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

        let inode_block: Vec<u8> = match disk.read(1) {
            Ok(bytes) => bytes,
            Err(_e) => return Err(FileSystemError::DiskReadFailure),
        };

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
    fn parse_path(path: &str) -> Vec<&str> {
        path.split('/').filter(|s| !s.is_empty()).collect()
    }

    // return directory entry metadata for a path (searches root and nested dirs)
    fn get_entry_metadata(
        &mut self,
        path: &str,
    ) -> Result<(usize, usize, bool, u16, u8, String), FileSystemError> {
        let parts = SimpleFileSystem::<BlockDisk>::parse_path(path);
        if parts.is_empty() {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        // find parent block and entry offset
        let (parent, base) = if parts.len() == 1 {
            (None, parts[0])
        } else {
            (
                self.lookup_path(&parts[..parts.len() - 1].join("/")),
                parts[parts.len() - 1],
            )
        };
        let block_index = if let Some(pin) = parent {
            let p = self.get_inode(pin)?;
            let ptr = p.direct[0] as usize;
            if ptr == 0 {
                return Err(FileSystemError::MiscellaneousFailure);
            }
            ptr
        } else {
            1 + self.superblock.num_inode_blocks as usize
        };
        let block = self
            .disk
            .read(block_index)
            .map_err(|_| FileSystemError::DiskReadFailure)?;
        let entries = BLOCK_SIZE / DIR_ENTRY_SIZE;
        for i in 0..entries {
            let off = i * DIR_ENTRY_SIZE;
            let name_bytes = &block[off..off + DIR_NAME_LEN];
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(DIR_NAME_LEN);
            if end == 0 {
                continue;
            }
            if let Ok(entry_name) = std::str::from_utf8(&name_bytes[..end]) {
                if entry_name == base {
                    let inum_slice = &block[off + DIR_NAME_LEN..off + DIR_NAME_LEN + 4];
                    let inum_bytes: [u8; 4] = inum_slice
                        .try_into()
                        .map_err(|_| FileSystemError::MiscellaneousFailure)?;
                    let inum = SimpleFileSystem::<BlockDisk>::slice_to_u32(&inum_bytes) as usize;
                    let entry_type = block[off + DIR_NAME_LEN + 4];
                    let perms_slice = &block[off + DIR_NAME_LEN + 5..off + DIR_NAME_LEN + 7];
                    let perms_bytes: [u8; 2] = perms_slice.try_into().unwrap_or([0u8; 2]);
                    let perms = u16::from_be_bytes(perms_bytes);
                    let roles = block[off + DIR_NAME_LEN + 7];
                    let ext_slice =
                        &block[off + DIR_NAME_LEN + 8..off + DIR_NAME_LEN + 8 + DIR_EXT_LEN];
                    let ext = match std::str::from_utf8(ext_slice) {
                        Ok(s) => s.trim_matches(char::from(0)).to_string(),
                        Err(_) => String::new(),
                    };
                    return Ok((inum, off, entry_type == 1u8, perms, roles, ext));
                }
            }
        }
        Err(FileSystemError::MiscellaneousFailure)
    }

    fn check_access(&self, entry_roles: u8, caller_role: u8) -> bool {
        if entry_roles == 0 {
            return true;
        }
        (entry_roles & caller_role) != 0
    }

    // try to find an inode by matching the basename across the whole filesystem
    fn find_inode_by_basename(
        &mut self,
        name: &str,
    ) -> Result<(usize, bool, u16, u8), FileSystemError> {
        let files = self.list_files()?;
        for (fullpath, inum, _data, is_dir, perms, roles, _ext) in files {
            // extract basename from fullpath
            let basename = match fullpath.rsplit('/').next() {
                Some(b) => b,
                None => &fullpath,
            };
            if basename == name {
                return Ok((inum, is_dir, perms, roles));
            }
        }
        Err(FileSystemError::MiscellaneousFailure)
    }

    pub fn read_named_with_role(
        &mut self,
        name: &str,
        data: &mut Vec<u8>,
        offset: usize,
        caller_role: u8,
    ) -> Result<usize, FileSystemError> {
        // Try exact path lookup first; if that fails, try finding by basename anywhere in the tree.
        let (inum, _off, is_dir, _perms, roles, _ext) = match self.get_entry_metadata(name) {
            Ok(tuple) => tuple,
            Err(_) => {
                let (inum2, is_dir2, perms2, roles2) = self.find_inode_by_basename(name)?;
                (inum2, 0usize, is_dir2, perms2, roles2, String::new())
            }
        };
        if is_dir {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        if !self.check_access(roles, caller_role) {
            return Err(FileSystemError::PermissionDenied);
        }
        self.read(inum, data, offset)
    }

    pub fn write_named_with_role(
        &mut self,
        name: &str,
        data: Vec<u8>,
        offset: usize,
        caller_role: u8,
    ) -> Result<usize, FileSystemError> {
        let (inum, _off, is_dir, _perms, roles, _ext) = match self.get_entry_metadata(name) {
            Ok(tuple) => tuple,
            Err(_) => {
                let (inum2, is_dir2, perms2, roles2) = self.find_inode_by_basename(name)?;
                (inum2, 0usize, is_dir2, perms2, roles2, String::new())
            }
        };
        if is_dir {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        if !self.check_access(roles, caller_role) {
            return Err(FileSystemError::PermissionDenied);
        }
        self.write(inum, data, offset)
    }

    pub fn remove_named_with_role(
        &mut self,
        name: &str,
        caller_role: u8,
    ) -> Result<bool, FileSystemError> {
        let (inum, _off, _is_dir, _perms, roles, _ext) = match self.get_entry_metadata(name) {
            Ok(tuple) => tuple,
            Err(_) => {
                let (inum2, is_dir2, perms2, roles2) = self.find_inode_by_basename(name)?;
                (inum2, 0usize, is_dir2, perms2, roles2, String::new())
            }
        };
        if !self.check_access(roles, caller_role) {
            return Err(FileSystemError::PermissionDenied);
        }
        self.remove(inum)
    }

    fn lookup_dir_in_block(block: &Vec<u8>, name: &str) -> Option<(usize, usize)> {
        let entries = BLOCK_SIZE / DIR_ENTRY_SIZE;
        for i in 0..entries {
            let off = i * DIR_ENTRY_SIZE;
            let name_bytes = &block[off..off + DIR_NAME_LEN];
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(DIR_NAME_LEN);
            if end == 0 {
                continue;
            }
            if let Ok(entry_name) = std::str::from_utf8(&name_bytes[..end]) {
                if entry_name == name {
                    let inum_bytes: [u8; 4] = block[off + DIR_NAME_LEN..off + DIR_NAME_LEN + 4]
                        .try_into()
                        .unwrap();
                    let inum = SimpleFileSystem::<BlockDisk>::slice_to_u32(&inum_bytes) as usize;
                    return Some((inum, off));
                }
            }
        }
        None
    }

    fn lookup_dir(&self, name: &str) -> Option<usize> {
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
                let inum_bytes: [u8; 4] = self.dir_block
                    [off + DIR_NAME_LEN..off + DIR_NAME_LEN + 4]
                    .try_into()
                    .unwrap();
                let inum = SimpleFileSystem::<BlockDisk>::slice_to_u32(&inum_bytes) as usize;
                return Some(inum);
            }
        }
        None
    }

    fn lookup_path(&mut self, path: &str) -> Option<usize> {
        let parts = SimpleFileSystem::<BlockDisk>::parse_path(path);
        if parts.is_empty() {
            return None;
        }
        // start at root dir block (owned clone so we can swap in deeper blocks)
        let mut current_block: Vec<u8> = self.dir_block.clone();
        let mut inum: Option<usize> = None;
        for (idx, part) in parts.iter().enumerate() {
            if idx == 0 {
                match SimpleFileSystem::<BlockDisk>::lookup_dir_in_block(&current_block, part) {
                    Some((n, _off)) => {
                        inum = Some(n);
                    }
                    None => return None,
                }
            } else {
                // for deeper levels, we need to read the directory block using previously found inum
                if let Some(parent_inum) = inum {
                    // assume directories are represented by an inode whose first direct pointer points to its dir block
                    let parent_inode = match self.get_inode(parent_inum) {
                        Ok(i) => i,
                        Err(_) => return None,
                    };
                    let dir_block_ptr = parent_inode.direct[0] as usize;
                    if dir_block_ptr == 0 {
                        return None;
                    }
                    let block = match self.disk.read(dir_block_ptr) {
                        Ok(b) => b,
                        Err(_) => return None,
                    };
                    match SimpleFileSystem::<BlockDisk>::lookup_dir_in_block(&block, part) {
                        Some((n, _off)) => {
                            inum = Some(n);
                            current_block = block;
                        }
                        None => return None,
                    }
                } else {
                    return None;
                }
            }
        }
        inum
    }

    fn add_path_entry(
        &mut self,
        parent_inum: Option<usize>,
        name: &str,
        inumber: usize,
        is_dir: bool,
        perms: u16,
        roles: u8,
        ext: Option<&str>,
    ) -> Result<(), FileSystemError> {
        let block_index = if let Some(pin) = parent_inum {
            let parent_inode = self.get_inode(pin)?;
            let ptr = parent_inode.direct[0] as usize;
            if ptr == 0 {
                return Err(FileSystemError::MiscellaneousFailure);
            }
            ptr
        } else {
            1 + self.superblock.num_inode_blocks as usize
        };
        let mut block = self
            .disk
            .read(block_index)
            .map_err(|_| FileSystemError::DiskReadFailure)?;
        let entries = BLOCK_SIZE / DIR_ENTRY_SIZE;
        for i in 0..entries {
            let off = i * DIR_ENTRY_SIZE;
            let name_bytes = &block[off..off + DIR_NAME_LEN];
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(DIR_NAME_LEN);
            if end == 0 {
                // free slot
                for (j, &b) in name.as_bytes().iter().enumerate() {
                    block[off + j] = b;
                }
                if name.len() < DIR_NAME_LEN {
                    block[off + name.len()] = 0;
                }
                block[off + DIR_NAME_LEN..off + DIR_NAME_LEN + 4]
                    .copy_from_slice(&(inumber as u32).to_be_bytes());
                block[off + DIR_NAME_LEN + 4] = if is_dir { 1u8 } else { 0u8 };
                block[off + DIR_NAME_LEN + 5..off + DIR_NAME_LEN + 7]
                    .copy_from_slice(&perms.to_be_bytes());
                block[off + DIR_NAME_LEN + 7] = roles;
                if let Some(exts) = ext {
                    let mut ext_bytes = [0u8; DIR_EXT_LEN];
                    for (k, &b) in exts.as_bytes().iter().enumerate().take(DIR_EXT_LEN) {
                        ext_bytes[k] = b;
                    }
                    block[off + DIR_NAME_LEN + 8..off + DIR_NAME_LEN + 8 + DIR_EXT_LEN]
                        .copy_from_slice(&ext_bytes);
                }
                self.disk
                    .write(block_index, block.clone())
                    .map_err(|_| FileSystemError::DiskWriteFailure)?;
                if block_index == 1 + self.superblock.num_inode_blocks as usize {
                    self.dir_block = block.clone();
                }
                return Ok(());
            }
        }
        Err(FileSystemError::MiscellaneousFailure)
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
                let mut new_block = self.dir_block.clone();
                // name
                for (j, &b) in name.as_bytes().iter().enumerate() {
                    new_block[off + j] = b;
                }
                if name.len() < DIR_NAME_LEN {
                    new_block[off + name.len()] = 0;
                }
                // inumber
                new_block[off + DIR_NAME_LEN..off + DIR_NAME_LEN + 4]
                    .copy_from_slice(&(inumber as u32).to_be_bytes());
                // default type = file (0), default perms 0o644, roles 0, ext blank
                new_block[off + DIR_NAME_LEN + 4] = 0u8; // entry_type
                new_block[off + DIR_NAME_LEN + 5..off + DIR_NAME_LEN + 7]
                    .copy_from_slice(&(0o644u16).to_be_bytes());
                new_block[off + DIR_NAME_LEN + 7] = 0u8; // roles
                                                         // extension left zeroed
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

    pub fn create_named(&mut self, name: &str) -> Result<usize, FileSystemError> {
        // backward-compatible wrapper: defaults
        self.create_named_with_attrs(name, 0o644, 0u8, None)
    }

    pub fn create_named_with_attrs(
        &mut self,
        name: &str,
        perms: u16,
        roles: u8,
        ext: Option<&str>,
    ) -> Result<usize, FileSystemError> {
        // allow path like "a/b/c"; create in parent and add entry
        let parts = SimpleFileSystem::<BlockDisk>::parse_path(name);
        if parts.is_empty() {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        let (parent, base) = if parts.len() == 1 {
            (None, parts[0])
        } else {
            (
                self.lookup_path(&parts[..parts.len() - 1].join("/")),
                parts[parts.len() - 1],
            )
        };
        if self.lookup_path(name).is_some() {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        let inum = self.create()?;
        self.add_path_entry(parent, base, inum, false, perms, roles, ext)?;
        Ok(inum)
    }

    pub fn remove_named(&mut self, name: &str) -> Result<bool, FileSystemError> {
        if let Some(inum) = self.lookup_path(name) {
            self.remove(inum)?;
            // remove dir entry from parent
            let parts = SimpleFileSystem::<BlockDisk>::parse_path(name);
            let parent = if parts.len() == 1 {
                None
            } else {
                self.lookup_path(&parts[..parts.len() - 1].join("/"))
            };
            if let Some(p) = parent {
                // remove from parent's dir block
                // TODO: implement remove in subdir; for now, only support root
                if p == 0 {
                    let _ = self.remove_dir(parts[parts.len() - 1]);
                }
            } else {
                let _ = self.remove_dir(parts[0]);
            }
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
        if let Some(inum) = self.lookup_path(name) {
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
        if let Some(inum) = self.lookup_path(name) {
            self.write(inum, data, offset)
        } else {
            Err(FileSystemError::MiscellaneousFailure)
        }
    }

    pub fn create_dir(
        &mut self,
        path: &str,
        perms: u16,
        roles: u8,
    ) -> Result<usize, FileSystemError> {
        let parts = SimpleFileSystem::<BlockDisk>::parse_path(path);
        if parts.is_empty() {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        let (parent, base) = if parts.len() == 1 {
            (None, parts[0])
        } else {
            (
                self.lookup_path(&parts[..parts.len() - 1].join("/")),
                parts[parts.len() - 1],
            )
        };
        if self.lookup_path(path).is_some() {
            return Err(FileSystemError::MiscellaneousFailure);
        }
        let inum = self.create()?;
        // create a dir block for this inode
        let b = self.allocate_block()?;
        // write empty dir block
        self.disk
            .write(b, vec![0; BLOCK_SIZE])
            .map_err(|_| FileSystemError::DiskWriteFailure)?;
        // set inode's first direct pointer to this dir block
        let mut inode = self.get_inode(inum)?;
        inode.direct[0] = b as u32;
        inode.valid = 1;
        inode.size = 0;
        self.write_inode(inum, &inode)?;
        self.add_path_entry(parent, base, inum, true, perms, roles, None)?;
        Ok(inum)
    }

    pub fn list_files(
        &mut self,
    ) -> Result<Vec<(String, usize, Vec<u8>, bool, u16, u8, String)>, FileSystemError> {
        let mut results: Vec<(String, usize, Vec<u8>, bool, u16, u8, String)> = Vec::new();
        let root_block_index = 1 + self.superblock.num_inode_blocks as usize;

        let root_block = match self.disk.read(root_block_index) {
            Ok(b) => b,
            Err(_) => return Err(FileSystemError::DiskReadFailure),
        };
        self.list_dir_recursive(&root_block, "", 0, &mut results);
        Ok(results)
    }

    fn list_dir_recursive(
        &mut self,
        block: &Vec<u8>,
        prefix: &str,
        depth: usize,
        results: &mut Vec<(String, usize, Vec<u8>, bool, u16, u8, String)>,
    ) {
        if depth > 10 {
            return;
        }
        let entries = BLOCK_SIZE / DIR_ENTRY_SIZE;
        for i in 0..entries {
            let off = i * DIR_ENTRY_SIZE;
            let name_bytes = &block[off..off + DIR_NAME_LEN];
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
            let full_path = if prefix.is_empty() {
                entry_name.clone()
            } else {
                format!("{}/{}", prefix, entry_name)
            };
            let inum_slice = &block[off + DIR_NAME_LEN..off + DIR_NAME_LEN + 4];
            let inum_bytes: [u8; 4] = match inum_slice.try_into() {
                Ok(arr) => arr,
                Err(_) => continue,
            };
            let inum = SimpleFileSystem::<BlockDisk>::slice_to_u32(&inum_bytes) as usize;
            let entry_type = block[off + DIR_NAME_LEN + 4];
            let perms_slice = &block[off + DIR_NAME_LEN + 5..off + DIR_NAME_LEN + 7];
            let perms_bytes: [u8; 2] = match perms_slice.try_into() {
                Ok(arr) => arr,
                Err(_) => [0u8; 2],
            };
            let perms = u16::from_be_bytes(perms_bytes);
            let roles = block[off + DIR_NAME_LEN + 7];
            let ext_slice = &block[off + DIR_NAME_LEN + 8..off + DIR_NAME_LEN + 8 + DIR_EXT_LEN];
            let ext = match std::str::from_utf8(ext_slice) {
                Ok(s) => s.trim_matches(char::from(0)).to_string(),
                Err(_) => String::new(),
            };
            let mut data: Vec<u8> = Vec::new();
            if inum != 0 && entry_type == 0u8 {
                let _ = self.read(inum, &mut data, 0);
            }
            let is_dir = entry_type == 1u8;
            results.push((full_path.clone(), inum, data, is_dir, perms, roles, ext));
            if is_dir {
                if let Ok(parent_inode) = self.get_inode(inum) {
                    let dir_ptr = parent_inode.direct[0] as usize;
                    if dir_ptr != 0 {
                        if let Ok(child_block) = self.disk.read(dir_ptr) {
                            self.list_dir_recursive(&child_block, &full_path, depth + 1, results);
                        }
                    }
                }
            }
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
