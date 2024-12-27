use aho_corasick::AhoCorasick;
use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    thread::{self},
    time::{Duration, Instant},
};

use crate::encfile::EncFile;

const NUM_OF_THREADS: u32 = 12;
const MAX_KEY: u32 = 0xFF_FF_FF_FF;

fn lin_space(start: u32, end: u32, num: u32) -> Vec<u32> {
    let mut res = vec![];
    let step = (end - start) / (num - 1);

    for i in 0..num - 1 {
        res.push(i * step + start);
    }

    res.push(end);
    res
}

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

fn do_scan(
    path: String,
    key_start: u32,
    key_end: u32,
    done: Arc<AtomicU32>,
    matches: Arc<Mutex<Vec<u32>>>,
) {
    let mut file = EncFile::new(path);
    let searcher = AhoCorasick::new(magics()).unwrap();

    for key in key_start..=key_end {
        file.decrypt(key);

        if searcher.is_match(&file.decrypted_content) {
            let mut matches = matches.lock().unwrap();
            matches.push(key);
            drop(matches);
            // println!("Match key {:#x}", key);
        }

        done.fetch_add(1, Ordering::SeqCst);
    }
}

pub struct Scanner {
    pub path: String,
    timestamp: Instant,
    done: usize,
    matches: Arc<Mutex<Vec<u32>>>,
}

impl Scanner {
    pub fn new(path: String) -> Self {
        Scanner {
            path,
            done: 0,
            timestamp: Instant::now(),
            matches: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn scan(&mut self) -> Vec<u32> {
        let chunks = lin_space(0, MAX_KEY, NUM_OF_THREADS);

        let mut handles = vec![];
        let done = Arc::new(AtomicU32::new(0));

        for i in 0..NUM_OF_THREADS as usize - 1 {
            let key_start = chunks[i] + 1;
            let key_end = chunks[i + 1];
            let path = self.path.clone();
            let done = done.clone();
            let matches = self.matches.clone();

            let handle = thread::spawn(move || {
                do_scan(path, key_start, key_end, done, matches);
            });
            handles.push(handle);
        }

        let all_done = || handles.iter().all(|handle| handle.is_finished());

        loop {
            self.timestamp = Instant::now();
            self.done = done.load(Ordering::Relaxed) as usize;
            thread::sleep(Duration::from_millis(3000));
            let done_now = done.load(Ordering::Relaxed) as usize;
            let done_diff = done_now - self.done;
            self.done = done_now;
            self.report_progress(done_diff);

            if all_done() {
                break;
            }
        }

        for handle in handles {
            handle.join().unwrap();
        }

        self.matches.lock().unwrap().clone()
    }

    fn report_progress(&self, done_diff: usize) {
        let speed = (done_diff as f64 * 1000.0) / self.timestamp.elapsed().as_millis() as f64;
        let percent = self.done as f64 / 0xFF_FF_FF_FFu64 as f64 * 100.0;
        let matches = self.matches.lock().unwrap();
        let found = matches.len();
        drop(matches);

        print!(
            "\rProcessing {}% ({} iters/sec) found: {}",
            percent as usize, speed as usize, found
        );
        io::stdout().flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linspace() {
        assert_eq!(lin_space(1, MAX_KEY, 4).len(), 4);
    }
}
