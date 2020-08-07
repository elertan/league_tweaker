fn main() {
    println!("Launching launcher...");
    let result = std::process::Command::new("C:\\Riot Games\\League of Legends\\LeagueClient.exe")
        .status()
        .expect("Failed to LeagueClient");
    println!("Status: {}", result);

    std::fs::copy(
        "..\\..\\..\\proxy\\target\\release\\proxy.exe",
        "C:\\Riot Games\\League of Legends\\LeagueClientUx.exe",
    )
    .expect("Failed to copy over proxy");
}
