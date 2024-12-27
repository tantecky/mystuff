use std::{
    fs::{self, File},
    io::Read,
};

#[derive(Debug)]
pub struct EncFile {
    path: String,
    orig_content: Vec<u8>,
    pub decrypted_content: Vec<u8>,
    size: u64,
}

fn key_size(key: u32) -> u32 {
    if key > 0xFFFFFF {
        4
    } else if key > 0xFFFF {
        3
    } else if key > 0xFF {
        2
    } else {
        1
    }
}

fn key_2_vec(key: u32) -> Vec<u8> {
    vec![
        (key & 0xFF) as u8,
        ((key >> 8) & 0xFF) as u8,
        ((key >> 16) & 0xFF) as u8,
        ((key >> 24) & 0xFF) as u8,
    ]
}

impl EncFile {
    pub fn new(path: String) -> Self {
        let mut file = EncFile {
            path,
            orig_content: vec![],
            decrypted_content: vec![],
            size: 0,
        };
        file.load();
        file
    }

    fn load(&mut self) {
        let path = &self.path;
        let mut file = File::open(path).expect("unable to open file");
        let metadata = fs::metadata(path).expect("unable to read metadata");
        let size = metadata.len();
        self.size = size;
        let mut buffer = vec![0; size as usize];
        file.read_exact(&mut buffer).expect("buffer overflow");
        self.orig_content = buffer;
    }
    pub fn decrypt(&mut self, key: u32) {
        let key_size = key_size(key) as usize;
        let key_vec = key_2_vec(key);

        if self.decrypted_content.is_empty() {
            self.decrypted_content = self.orig_content.to_vec();
        }

        for i in 0..self.size as usize {
            self.decrypted_content[i] = self.orig_content[i] ^ key_vec[i % key_size];
        }
    }

    pub fn write_decrypted(&mut self, key: u32) {
        self.decrypt(key);
        let filename = format!("{}.bin", key);
        fs::write(filename, &self.decrypted_content).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_2_vec() {
        let key: u32 = 0xAABBCCDD;
        let vec = key_2_vec(key);
        assert_eq!(vec[0], 0xDD);
        assert_eq!(vec[1], 0xCC);
        assert_eq!(vec[2], 0xBB);
        assert_eq!(vec[3], 0xAA);
    }

    #[test]
    fn test_key_size() {
        assert_eq!(key_size(0xFF), 1);
        assert_eq!(key_size(0xFFFF), 2);
        assert_eq!(key_size(0xFFFFFF), 3);
        assert_eq!(key_size(0xFFFFFFFF), 4);
    }

    #[test]
    fn test_decrypt() {
        let mut file = EncFile {
            path: "".to_owned(),
            orig_content: vec![0xAA, 0xBB, 0xCC, 0xDD],
            decrypted_content: vec![],
            size: 4,
        };

        file.decrypt(0xFF);
        assert_eq!(file.decrypted_content[0], 0x55);
        assert_eq!(file.decrypted_content[1], 0x44);
        assert_eq!(file.decrypted_content[2], 0x33);
        assert_eq!(file.decrypted_content[3], 0x22);

        file.decrypt(0xDEADBEEF);
        assert_eq!(file.decrypted_content[0], 69);
        assert_eq!(file.decrypted_content[1], 5);
        assert_eq!(file.decrypted_content[2], 97);
        assert_eq!(file.decrypted_content[3], 3);
    }
}
