pub mod attr;
pub mod msg;
pub mod route;
pub mod socket;

use socket::{DumpError, NlSocket, dump};


fn main() {
    if let Err(err) = run() {
        eprintln!("route-nl: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DumpError> {
    let sock = NlSocket::open()?;
    for route in dump(sock.0)? {
        println!("{route}");
    }
    Ok(())
}


