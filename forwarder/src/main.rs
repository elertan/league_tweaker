fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    std::process::Command::new("C:\\Riot Games\\League of Legends\\proxy.exe")
        .args(args.as_slice())
        .spawn()
        .expect("Failed to spawn proxy");
}
