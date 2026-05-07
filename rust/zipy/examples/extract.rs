use std::env;

fn main() -> zipy::Result<()> {
    let mut args = env::args_os().skip(1);
    let archive = args.next().expect("usage: extract <archive.zip> <target>");
    let target = args.next().expect("usage: extract <archive.zip> <target>");

    zipy::extract(archive, target, zipy::Options::fast().overwrite())
}
