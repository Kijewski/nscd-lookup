use std::env::{args, current_exe};
use std::process::exit;

use nscd_lookup::lookup;

fn main() {
    let mut args = args().fuse();
    let exe = args.next();
    let Some(host) = args.next() else {
        usage(exe);
        exit(1);
    };

    let mut buf = Vec::new();
    match lookup(host, &mut buf) {
        Ok(Some(iter)) => {
            for addr in iter {
                println!("{addr}");
            }
        }
        Ok(None) => {
            eprintln!("No addresses.");
            exit(1);
        }
        Err(err) => {
            eprintln!("Could not lookup: {err}");
            exit(1);
        }
    }
}

fn usage(exe: Option<String>) {
    let (current_exe_result, current_exe_cow);
    let mut exe = exe.as_deref();
    if exe.is_none() {
        current_exe_result = current_exe().ok();
        if let Some(current_exe) = &current_exe_result {
            current_exe_cow = current_exe.to_string_lossy();
            exe = Some(&*current_exe_cow);
        }
    };
    eprintln!("Usage: {} <DOMAIN_NAME>", exe.unwrap_or("nscd-lookup"));
}
