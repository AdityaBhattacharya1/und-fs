use simplefs::disk::{BlockDisk, Disk};
use simplefs::fs::{FileSystem, FileSystemError, SimpleFileSystem};
use std::io::{self, Write};

fn main() {
    let mut maybe_disk: Option<BlockDisk> = None;
    let mut maybe_fs: Option<SimpleFileSystem<BlockDisk>> = None;

    loop {
        println!("\n=== SimpleFS Menu ===");
        println!("1. Create / Open Disk");
        println!("2. Format Filesystem");
        println!("3. Mount Filesystem");
        println!("4. Create File (Inode)");
        println!("5. Get File Stat (Size)");
        println!("6. Exit");
        print!("Enter choice: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        let choice = choice.trim();

        match choice {
            "1" => {
                let mut path = String::new();
                print!("Enter disk image path (e.g., disk.img): ");
                io::stdout().flush().unwrap();
                io::stdin().read_line(&mut path).unwrap();

                let mut blocks = String::new();
                print!("Enter number of blocks (e.g., 100): ");
                io::stdout().flush().unwrap();
                io::stdin().read_line(&mut blocks).unwrap();

                let path = path.trim().to_string();
                let num_blocks: usize = blocks.trim().parse().unwrap_or(100);

                match BlockDisk::open(path.clone(), num_blocks) {
                    Ok(disk) => {
                        println!("Disk '{}' opened with {} blocks.", path, num_blocks);
                        maybe_disk = Some(disk);
                    }
                    Err(_) => println!("Failed to open disk."),
                }
            }

            "2" => {
                if let Some(ref mut disk) = maybe_disk {
                    match SimpleFileSystem::format(disk.try_clone().expect("Failed to clone disk"))
                    {
                        Ok(()) => println!("Filesystem formatted successfully."),
                        Err(e) => println!("Format failed: {:?}", e),
                    }
                } else {
                    println!("No disk opened. Create a disk first.");
                }
            }

            "3" => {
                if let Some(disk) = maybe_disk.take() {
                    match SimpleFileSystem::mount(disk) {
                        Ok(fs) => {
                            println!("Filesystem mounted successfully.");
                            maybe_fs = Some(fs);
                        }
                        Err(e) => println!("Mount failed: {:?}", e),
                    }
                } else {
                    println!("No disk available. Format or open one first.");
                }
            }

            "4" => {
                if let Some(ref mut fs) = maybe_fs {
                    match fs.create() {
                        Ok(inumber) => println!("Created inode with number: {}", inumber),
                        Err(FileSystemError::NoFreeInodes) => println!("No free inodes available."),
                        Err(e) => println!("Error creating file: {:?}", e),
                    }
                } else {
                    println!("No mounted filesystem. Mount first.");
                }
            }

            "5" => {
                if let Some(ref fs) = maybe_fs {
                    let mut inumber_input = String::new();
                    print!("Enter inode number: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut inumber_input).unwrap();

                    let inumber: usize = inumber_input.trim().parse().unwrap_or(0);
                    match fs.stat(inumber) {
                        Ok(size) => println!("Inode {} size: {} bytes", inumber, size),
                        Err(e) => println!("Failed to get stat: {:?}", e),
                    }
                } else {
                    println!("No mounted filesystem. Mount first.");
                }
            }

            "6" => {
                println!("Exiting SimpleFS.");
                break;
            }

            _ => println!("Invalid choice."),
        }
    }
}
