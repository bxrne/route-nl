pub mod attr;
pub mod msg;
pub mod route;
pub mod socket;

use clap::{Parser, Subcommand};
use socket::{dump, DumpError, NlSocket};

#[derive(Parser)]
#[command(
    author = "Adam Byrne <adamrbyrne@gmail.com", 
    version, 
    about = "Linux netlink client",
    long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Dump,
    // Replace
}

fn run() -> Result<(), DumpError> {
    let args = Args::parse();

    match args.cmd {
        Commands::Dump => {
            let sock = NlSocket::open()?;
            for route in dump(sock.0)? {
                println!("{route}");
            }
            Ok(())
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("route-nl error: {err}");
        std::process::exit(1);
    }
}
