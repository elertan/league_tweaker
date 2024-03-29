fn main() {
    println!("Launching launcher...");
    let result = std::process::Command::new("C:\\Riot Games\\League of Legends\\LeagueClient.exe")
        .status()
        .expect("Failed to LeagueClient");
    println!("Status: {}", result);

    std::fs::copy(
        "C:\\Riot Games\\League of Legends\\LeagueClientUx.exe",
        "C:\\Riot Games\\League of Legends\\LeagueClientUx.exe.bak",
    )
    .expect("Failed to backup league client ux");

    std::fs::copy(
        "..\\..\\..\\forwarder\\target\\release\\forwarder.exe",
        "C:\\Riot Games\\League of Legends\\LeagueClientUx.exe",
    )
    .expect("Failed to copy over proxy");

    std::fs::copy(
        "..\\..\\..\\proxy\\target\\release\\proxy.exe",
        "C:\\Riot Games\\League of Legends\\proxy.exe",
    )
    .expect("Failed to copy over proxy");
}
