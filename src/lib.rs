#[derive(Debug)]
pub struct Color;

impl Color {
    pub const RESET: &'static str = "\x1b[0m";
    pub const BOLD: &'static str = "\x1b[1m";
    pub const RED: &'static str = "\x1b[31m";
    pub const GREEN: &'static str = "\x1b[32m";
    pub const YELLOW: &'static str = "\x1b[33m";
    pub const BLUE: &'static str = "\x1b[34m";
    pub const MAGENTA: &'static str = "\x1b[35m";
    pub const CYAN: &'static str = "\x1b[36m";
    pub const WHITE: &'static str = "\x1b[37m";

    pub fn wrap(text: &str, color: &str) -> String {
        format!("{}{}{}", color, text, Self::RESET)
    }

    pub fn rgb(r: u8, g: u8, b: u8) -> String {
        format!("\x1b[38;5;{};{};{}m", r, g, b)
    }
}

#[macro_export]
macro_rules! msg {
    ( $( $x:tt )* ) => {
        {
            println!("{} {}", Color::wrap("[+]", Color::GREEN), format!($($x)*));
        }
    };
}

#[macro_export]
macro_rules! err {
    ( $( $x:tt )* ) => {
        {
            println!("{} {}", Color::wrap("[-]", Color::RED), format!($($x)*));
        }
    };
}

#[macro_export]
macro_rules! log {
    ( $( $x:tt )* ) => {
        {
            println!("{} {}", Color::wrap("[*]", &format!("{}{}", Color::BOLD, Color::YELLOW)), format!($($x)*));
        }
    };
}
