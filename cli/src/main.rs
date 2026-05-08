//! envrypt CLI - Encrypt/decrypt .env file values

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use envcrypt_lib::{Config, EnvcryptLoader, ENCRYPTED_PREFIX};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "envcrypt")]
#[command(about = "Encrypt and decrypt .env file values", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize envrypt with a new or existing key
    Init {
        /// Use a specific key (hex encoded, 64 chars)
        #[arg(short, long)]
        key: Option<String>,

        /// Generate a random key automatically
        #[arg(short, long)]
        generate: bool,

        /// Config file path (default: ~/.envcrypt.yaml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Encrypt values in a .env file
    Encrypt {
        /// Input .env file
        file: PathBuf,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Modify file in-place
        #[arg(short = 'i', long)]
        in_place: bool,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Use this key instead of config file
        #[arg(short, long)]
        key: Option<String>,

        /// Glob patterns to exclude from encryption (e.g. 'LOG_*')
        #[arg(short = 'e', long)]
        exclude: Vec<String>,
    },

    /// Decrypt values in a .env file
    Decrypt {
        /// Input .env file
        file: PathBuf,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Modify file in-place
        #[arg(short = 'i', long)]
        in_place: bool,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Use this key instead of config file
        #[arg(short, long)]
        key: Option<String>,
    },

    /// Encrypt a single value
    EncryptValue {
        /// Value to encrypt
        value: String,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Use this key instead of config file
        #[arg(short, long)]
        key: Option<String>,
    },

    /// Decrypt a single value
    DecryptValue {
        /// Value to decrypt (with or without encrypted: prefix)
        value: String,

        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Use this key instead of config file
        #[arg(short, long)]
        key: Option<String>,
    },

    /// Show current config path and key info
    Status {
        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            key,
            generate,
            config,
        } => cmd_init(key, generate, config),

        Commands::Encrypt {
            file,
            output,
            in_place,
            config,
            key,
            exclude,
        } => cmd_encrypt(file, output, in_place, config, key, exclude),

        Commands::Decrypt {
            file,
            output,
            in_place,
            config,
            key,
        } => cmd_decrypt(file, output, in_place, config, key),

        Commands::EncryptValue { value, config, key } => cmd_encrypt_value(value, config, key),

        Commands::DecryptValue { value, config, key } => cmd_decrypt_value(value, config, key),

        Commands::Status { config } => cmd_status(config),
    }
}

fn cmd_init(key: Option<String>, generate: bool, config_path: Option<PathBuf>) -> Result<()> {
    let config_file = config_path
        .clone()
        .unwrap_or_else(Config::default_path);

    // Check if config already exists
    if config_file.exists() {
        eprintln!("⚠️  Config already exists at: {}", config_file.display());
        eprint!("Overwrite? [y/N] ");
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let final_key = if let Some(k) = key {
        // Validate provided key
        let _ = EnvcryptLoader::from_key(&k).context("Invalid key format")?;
        k
    } else if generate {
        EnvcryptLoader::generate_key()
    } else {
        // Interactive: ask user
        eprint!("Enter encryption key (64 hex chars) or press Enter to generate: ");
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            EnvcryptLoader::generate_key()
        } else {
            let _ = EnvcryptLoader::from_key(input).context("Invalid key format")?;
            input.to_string()
        }
    };

    // Save config
    let cfg = Config { key: final_key.clone() };
    cfg.save(config_path.as_deref())?;

    println!("✅ Config saved to: {}", config_file.display());
    println!("🔑 Key: {}...{}", &final_key[..8], &final_key[final_key.len()-8..]);
    println!("\n⚠️  Keep this key safe! You'll need it to decrypt your .env files.");

    Ok(())
}

fn get_loader(config: Option<PathBuf>, key: Option<String>) -> Result<EnvcryptLoader> {
    if let Some(k) = key {
        EnvcryptLoader::from_key(&k).context("Invalid key")
    } else {
        EnvcryptLoader::from_config(config.as_deref()).context("Failed to load config")
    }
}

fn cmd_encrypt(
    file: PathBuf,
    output: Option<PathBuf>,
    in_place: bool,
    config: Option<PathBuf>,
    key: Option<String>,
    exclude: Vec<String>,
) -> Result<()> {
    let loader = get_loader(config, key)?;
    let content = fs::read_to_string(&file)
        .with_context(|| format!("Failed to read {}", file.display()))?;

    let encrypted = loader.encrypt_content(&content, &exclude)?;

    if in_place {
        fs::write(&file, &encrypted)?;
        eprintln!("✅ Encrypted in-place: {}", file.display());
    } else if let Some(out) = output {
        fs::write(&out, &encrypted)?;
        eprintln!("✅ Encrypted to: {}", out.display());
    } else {
        print!("{}", encrypted);
    }

    Ok(())
}

fn cmd_decrypt(
    file: PathBuf,
    output: Option<PathBuf>,
    in_place: bool,
    config: Option<PathBuf>,
    key: Option<String>,
) -> Result<()> {
    let loader = get_loader(config, key)?;
    let content = fs::read_to_string(&file)
        .with_context(|| format!("Failed to read {}", file.display()))?;

    let decrypted = loader.decrypt_content(&content)?;

    if in_place {
        fs::write(&file, &decrypted)?;
        eprintln!("✅ Decrypted in-place: {}", file.display());
    } else if let Some(out) = output {
        fs::write(&out, &decrypted)?;
        eprintln!("✅ Decrypted to: {}", out.display());
    } else {
        print!("{}", decrypted);
    }

    Ok(())
}

fn cmd_encrypt_value(value: String, config: Option<PathBuf>, key: Option<String>) -> Result<()> {
    let loader = get_loader(config, key)?;
    let encrypted = loader.encrypt(&value)?;
    println!("{}", encrypted);
    Ok(())
}

fn cmd_decrypt_value(value: String, config: Option<PathBuf>, key: Option<String>) -> Result<()> {
    let loader = get_loader(config, key)?;

    let to_decrypt = if value.starts_with(ENCRYPTED_PREFIX) {
        value
    } else {
        format!("{}{}", ENCRYPTED_PREFIX, value)
    };

    let decrypted = loader.decrypt(&to_decrypt)?;
    println!("{}", decrypted);
    Ok(())
}

fn cmd_status(config: Option<PathBuf>) -> Result<()> {
    let config_path = config.unwrap_or_else(Config::default_path);

    println!("Config path: {}", config_path.display());

    if config_path.exists() {
        match Config::load(Some(&config_path)) {
            Ok(cfg) => {
                println!("Status: ✅ Configured");
                println!(
                    "Key: {}...{}",
                    &cfg.key[..8],
                    &cfg.key[cfg.key.len() - 8..]
                );
            }
            Err(e) => {
                println!("Status: ❌ Invalid config");
                println!("Error: {}", e);
            }
        }
    } else {
        println!("Status: ❌ Not initialized");
        println!("Run 'envrypt init' to set up.");
    }

    Ok(())
}
