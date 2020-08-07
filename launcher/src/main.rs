fn main() {
    println!("Launching launcher...");
    let result = std::process::Command::new("C:\\Riot Games\\League of Legends\\LeagueClient.exe")
        .status()
        .unwrap();
    println!("Status: {}", result);
}
