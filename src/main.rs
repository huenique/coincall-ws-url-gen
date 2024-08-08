use clap::{Arg, Command};
use hex::encode;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

fn generate_wss_url(
    api_key: &str,
    api_secret: &str,
    uuid: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let code = "10";
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .to_string();

    let verb = "GET";
    let uri = "/users/self/verify";
    let auth = format!("{}{}?uuid={}&ts={}", verb, uri, api_key, ts);

    let mut mac =
        HmacSha256::new_from_slice(api_secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(auth.as_bytes());
    let sign = encode(mac.finalize().into_bytes()).to_uppercase();

    let url = if let Some(uuid) = uuid {
        format!(
            "wss://ws.coincall.com/options?code={}&uuid={}&ts={}&sign={}&apiKey={}",
            code, uuid, ts, sign, api_key
        )
    } else {
        format!(
            "wss://ws.coincall.com/options?code={}&ts={}&sign={}&apiKey={}",
            code, ts, sign, api_key
        )
    };

    Ok(url)
}

fn get_command_line_args() -> (String, String, Option<String>) {
    let matches = Command::new("WSS URL Generator")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("Generates a WebSocket URL for Coincall API")
        .arg(
            Arg::new("api_key")
                .help("API key")
                .required(true)
                .value_name("API_KEY"),
        )
        .arg(
            Arg::new("api_secret")
                .help("API secret")
                .required(true)
                .value_name("API_SECRET"),
        )
        .arg(
            Arg::new("uuid")
                .help("UUID")
                .required(false)
                .value_name("UUID"),
        )
        .get_matches();

    let api_key = matches.get_one::<String>("api_key").unwrap().to_string();
    let api_secret = matches.get_one::<String>("api_secret").unwrap().to_string();
    let uuid = matches.get_one::<String>("uuid").map(|s| s.to_string());

    (api_key, api_secret, uuid)
}

fn main() {
    let (api_key, api_secret, uuid) = get_command_line_args();

    match generate_wss_url(&api_key, &api_secret, uuid.as_deref()) {
        Ok(url) => println!("WebSocket URL: {}", url),
        Err(e) => eprintln!("Error: {}", e),
    }
}
