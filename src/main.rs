use vxsym::{analyze, read_image, to_json, Output};

fn main() {
    let out = match std::env::args().nth(1) {
        Some(path) => match read_image(&path) {
            Ok(data) => analyze(&data),
            Err(_) => Output::empty(),
        },
        None => Output::empty(),
    };
    println!("{}", to_json(&out));
}
