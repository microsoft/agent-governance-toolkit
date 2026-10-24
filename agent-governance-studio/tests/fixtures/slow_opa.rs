// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Deliberately failing test executable: never returns a successful policy evaluation.

use std::{env, fs, path::Path, process::{self, Command}, thread, time::Duration};

fn main() {
    if env::args().any(|arg| arg == "--child") {
        let lock = Path::new(&env::var("TEMP").unwrap()).join("child-lock");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let _held_open_until_killed = options.open(lock).unwrap();
        thread::sleep(Duration::from_secs(120));
        return;
    }
    let child = Command::new(env::current_exe().unwrap()).arg("--child").spawn().unwrap();
    let temp = env::var("TEMP").unwrap();
    while !Path::new(&temp).join("child-lock").exists() {
        thread::sleep(Duration::from_millis(10));
    }
    let marker = env::var("STUDIO_TEST_PID_FILE").unwrap();
    fs::write(marker, format!("{}\n{}\n{}\n", process::id(), child.id(), temp)).unwrap();
    thread::sleep(Duration::from_secs(120));
}
