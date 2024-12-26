use aho_corasick::AhoCorasick;
use std::{
    io::{self, Write},
    time::Instant,
};

use crate::encfile::EncFile;

const REPORT_EACH: usize = 10_000_000;

fn magics() -> Vec<Vec<u8>> {
    vec![
        b"sqsh".to_vec(),
        b"hsqs".to_vec(),
        b"sqlz".to_vec(),
        b"qshs".to_vec(),
        b"tqsh".to_vec(),
        b"hsqt".to_vec(),
        b"shsq".to_vec(),
    ]
}

pub struct Scanner {
    pub path: String,
    timestamp: Instant,
    done: usize,
}

impl Scanner {
    pub fn new(path: String) -> Self {
        Scanner {
            path,
            done: 0,
            timestamp: Instant::now(),
        }
    }

    pub fn scan(&mut self) {
        let key_start: u32 = 1;
        let key_end: u32 = 0xFF_FF_FF_FF;

        self.timestamp = Instant::now();
        self.do_scan(self.path.to_owned(), key_start, key_end);
    }

    fn do_scan(&mut self, path: String, key_start: u32, key_end: u32) {
        let mut file = EncFile::new(path);
        let searcher = AhoCorasick::new(magics()).unwrap();

        for key in key_start..=key_end {
            file.decrypt(key);

            if searcher.is_match(&file.decrypted_content) {
                println!("Match key {:#x}", key);
            }

            self.done += 1;

            if self.done % REPORT_EACH == 0 {
                self.report_progress();
                self.timestamp = Instant::now();
            }
        }
    }

    fn report_progress(&self) {
        let speed = (REPORT_EACH as f64 * 1000.0) / self.timestamp.elapsed().as_millis() as f64;
        let percent = self.done as f64 / 0xFF_FF_FF_FFu64 as f64 * 100.0;
        print!(
            "\rProcessing {}% ({} iters/sec)",
            percent as usize, speed as usize
        );
        io::stdout().flush().unwrap();
    }
}
