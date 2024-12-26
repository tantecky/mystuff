use crate::encfile::EncFile;

pub struct Scanner {
    pub path: String,
    done: usize,
}

impl Scanner {
    pub fn new(path: String) -> Self {
        Scanner { path, done: 0 }
    }

    pub fn scan(&mut self) {
        let key_start: u32 = 1;
        let key_end: u32 = 0xFFFFFF;

        self.do_scan(self.path.to_owned(), key_start, key_end);
    }

    fn do_scan(&mut self, path: String, key_start: u32, key_end: u32) {
        let mut file = EncFile::new(path);

        for key in key_start..=key_end {
            file.decrypt(key);
            self.done += 1;
        }
    }
}
