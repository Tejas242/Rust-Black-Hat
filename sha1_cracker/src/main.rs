use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    time::Instant,
};

mod sha1;
use sha1::Sha1;

const SHA1_HEX_STRING_LENGTH: usize = 40;

struct Stats {
    attempts: u64,
    start_time: Instant,
}

impl Stats {
    fn new() -> Self {
        Stats {
            attempts: 0,
            start_time: Instant::now(),
        }
    }

    fn increment(&mut self) {
        self.attempts += 1;
    }

    fn elapsed_secs(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    fn attempts_per_sec(&self) -> f64 {
        self.attempts as f64 / self.elapsed_secs()
    }
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}

fn print_banner() {
    println!(
        "{}",
        r#"
              ____  _             _    ____                _
             / ___|| |__   __ _  / |  / ___|_ __ __ _  ___| | _____ _ __
             \___ \| '_ \ / _` | | | | |   | '__/ _` |/ __| |/ / _ \ '__|
              ___) | | | | (_| | | | | |___| | | (_| | (__|   <  __/ |
             |____/|_| |_|\__,_| |_|  \____|_|  \__,_|\___|_|\_\___|_|
"#
        .bright_cyan()
    );
    println!("{}", "A fast and efficient SHA1 hash cracker".bright_blue());
    println!("{}", "===================================".bright_blue());
}

fn print_usage() {
    println!("\n{}", "Usage:".bright_yellow());
    println!(
        "{}",
        "sha1_cracker <wordlist.txt> <sha1_hash>".bright_yellow()
    );
    println!("\n{}", "Example:".bright_yellow());
    println!(
        "{}",
        "sha1_cracker wordlist.txt 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8".bright_yellow()
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    clear_screen();
    print_banner();

    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        print_usage();
        return Ok(());
    }

    let hash_to_crack = args[2].trim();
    if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH {
        return Err("Invalid SHA1 hash length".into());
    }

    println!(
        "\n{} {}",
        "Target Hash:".bright_green(),
        hash_to_crack.bright_white()
    );

    let wordlist_file = File::open(&args[1])?;
    let reader = BufReader::new(wordlist_file);
    let total_lines = BufReader::new(File::open(&args[1])?).lines().count();

    let pb = ProgressBar::new(total_lines as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut stats = Stats::new();

    for line in reader.lines() {
        let line = line?;
        let password = line.trim();
        stats.increment();
        pb.inc(1);

        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();

        if hash_to_crack == &hash {
            pb.finish_with_message("Password found!");
            println!(
                "\n{} {}",
                "Password found:".bright_green(),
                password.bright_white().bold()
            );
            println!(
                "{} {:.2} seconds",
                "Time taken:".bright_green(),
                stats.elapsed_secs()
            );
            println!(
                "{} {:.2}/s",
                "Average speed:".bright_green(),
                stats.attempts_per_sec()
            );
            println!(
                "{} {}",
                "Attempts:".bright_green(),
                stats.attempts.to_string().bright_white()
            );
            return Ok(());
        }
    }

    pb.finish_with_message("Password not found");
    println!(
        "\n{} {}",
        "Result:".bright_red(),
        "Password not found in wordlist".bright_white()
    );
    println!(
        "{} {:.2} seconds",
        "Time taken:".bright_green(),
        stats.elapsed_secs()
    );
    println!(
        "{} {:.2}/s",
        "Average speed:".bright_green(),
        stats.attempts_per_sec()
    );
    println!(
        "{} {}",
        "Attempts:".bright_green(),
        stats.attempts.to_string().bright_white()
    );

    Ok(())
}
