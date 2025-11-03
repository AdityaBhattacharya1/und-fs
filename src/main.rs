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
        println!("4. Create File");
        println!("5. Get File Stat (Size)");
        println!("6. Read Named File");
        println!("7. Write Named File");
        println!("8. Delete Named File");
        println!("9. List Files");
        println!("0. Exit");
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
                    let mut path = String::new();
                    print!("Enter path (e.g. dir1/dir2/file) or leave empty for unnamed inode: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut path).unwrap();
                    let path = path.trim();
                    if path.is_empty() {
                        match fs.create() {
                            Ok(inumber) => {
                                println!("Created unnamed inode with number: {}", inumber)
                            }
                            Err(FileSystemError::NoFreeInodes) => {
                                println!("No free inodes available.")
                            }
                            Err(e) => println!("Error creating file: {:?}", e),
                        }
                        continue;
                    }

                    let mut typ = String::new();
                    print!("Create file or dir? (f/d): ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut typ).unwrap();
                    let is_dir = typ.trim().to_lowercase().starts_with('d');

                    let mut perms_in = String::new();
                    print!("Enter perms in octal (e.g. 644) or leave empty for default: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut perms_in).unwrap();
                    let perms = perms_in.trim().parse::<u16>().unwrap_or(644);

                    let mut roles_in = String::new();
                    print!("Enter role bits (0-255) or leave empty for 0: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut roles_in).unwrap();
                    let roles = roles_in.trim().parse::<u8>().unwrap_or(0u8);

                    if is_dir {
                        match fs.create_dir(path, perms, roles) {
                            Ok(inumber) => println!("Created dir '{}' inumber {}", path, inumber),
                            Err(e) => println!("Failed to create dir: {:?}", e),
                        }
                    } else {
                        let mut ext = String::new();
                        print!("Enter extension (e.g. txt) or leave empty: ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut ext).unwrap();
                        let _ext = ext.trim();
                        // create file with collected attrs
                        match fs.create_named_with_attrs(
                            path,
                            perms,
                            roles,
                            if _ext.is_empty() { None } else { Some(_ext) },
                        ) {
                            Ok(inumber) => {
                                println!("Created file '{}' inumber {}", path, inumber)
                            }
                            Err(e) => println!("Failed to create file: {:?}", e),
                        }
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
                if let Some(ref mut fs) = maybe_fs {
                    let mut name = String::new();
                    print!("Enter filename to read: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut name).unwrap();
                    let name = name.trim();

                    let mut offset_input = String::new();
                    print!("Enter offset: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut offset_input).unwrap();
                    let offset: usize = offset_input.trim().parse().unwrap_or(0);

                    let mut buf: Vec<u8> = Vec::new();
                    let mut role_in = String::new();
                    print!("Enter caller role (0-255) or leave empty for 0: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut role_in).unwrap();
                    let role = role_in.trim().parse::<u8>().unwrap_or(0u8);
                    match fs.read_named_with_role(name, &mut buf, offset, role) {
                        Ok(n) => {
                            println!("Read {} bytes:", n);
                            match std::str::from_utf8(&buf) {
                                Ok(s) => println!("{}", s),
                                Err(_) => println!("(binary) {:?}", buf),
                            }
                        }
                        Err(e) => println!("Read failed: {:?}", e),
                    }
                } else {
                    println!("No mounted filesystem. Mount first.");
                }
            }

            "7" => {
                if let Some(ref mut fs) = maybe_fs {
                    let mut name = String::new();
                    print!("Enter filename to write: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut name).unwrap();
                    let name = name.trim();

                    let mut offset_input = String::new();
                    print!("Enter offset: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut offset_input).unwrap();
                    let offset: usize = offset_input.trim().parse().unwrap_or(0);

                    let mut content = String::new();
                    print!("Enter data to write: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut content).unwrap();
                    let bytes = content.into_bytes();

                    let mut role_in = String::new();
                    print!("Enter caller role (0-255) or leave empty for 0: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut role_in).unwrap();
                    let role = role_in.trim().parse::<u8>().unwrap_or(0u8);
                    match fs.write_named_with_role(name, bytes, offset, role) {
                        Ok(n) => println!("Wrote {} bytes to '{}'", n, name),
                        Err(e) => println!("Write failed: {:?}", e),
                    }
                } else {
                    println!("No mounted filesystem. Mount first.");
                }
            }

            "8" => {
                if let Some(ref mut fs) = maybe_fs {
                    let mut name = String::new();
                    print!("Enter filename to delete: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut name).unwrap();
                    let name = name.trim();
                    let mut role_in = String::new();
                    print!("Enter caller role (0-255) or leave empty for 0: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut role_in).unwrap();
                    let role = role_in.trim().parse::<u8>().unwrap_or(0u8);
                    match fs.remove_named_with_role(name, role) {
                        Ok(true) => println!("Deleted '{}'.", name),
                        Ok(false) => println!("'{}' not found.", name),
                        Err(e) => println!("Delete failed: {:?}", e),
                    }
                } else {
                    println!("No mounted filesystem. Mount first.");
                }
            }

            "9" => {
                if let Some(ref mut fs) = maybe_fs {
                    match fs.list_files() {
                        Ok(files) => {
                            println!(
                                "{:<24} {:<6} {:<8} {:<6} {:<8} {:<6} {:<8} {}",
                                "Name", "Type", "Inumber", "Size", "Perms", "Roles", "Ext", "Data"
                            );
                            println!("{:-<120}", "");
                            for (name, inum, data, is_dir, perms, roles, ext) in files {
                                let size = data.len();
                                let preview = if size == 0 {
                                    "".to_string()
                                } else {
                                    match std::str::from_utf8(&data) {
                                        Ok(s) => {
                                            if s.len() > 40 {
                                                format!("{}...", &s[..40])
                                            } else {
                                                s.to_string()
                                            }
                                        }
                                        Err(_) => format!("{:?}", &data[..std::cmp::min(40, size)]),
                                    }
                                };
                                let ftype = if is_dir { "dir" } else { "file" };
                                println!(
                                    "{:<24} {:<6} {:<8} {:<6} {:<#06o} {:<6} {:<8} {}",
                                    name, ftype, inum, size, perms, roles, ext, preview
                                );
                            }
                        }
                        Err(e) => println!("Failed to list files: {:?}", e),
                    }
                } else {
                    println!("No mounted filesystem. Mount first.");
                }
            }

            "0" => {
                println!("Exiting.");
                break;
            }

            _ => println!("Invalid choice."),
        }
    }
}
