//! Password generation and TOTP codes.

use super::*;

pub fn generate_password(length: usize) -> Result<String> {
    generate_password_with_recipe(&PasswordRecipe::Random {
        length,
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
        avoid_ambiguous: true,
    })
}

/// A password recipe shared by the desktop generator and item editors.
/// Defaults are deliberately strong while still allowing sites with narrow
/// password policies to opt out of individual character classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PasswordRecipe {
    Random {
        length: usize,
        #[serde(default = "default_true")]
        uppercase: bool,
        #[serde(default = "default_true")]
        lowercase: bool,
        #[serde(default = "default_true")]
        numbers: bool,
        #[serde(default = "default_true")]
        symbols: bool,
        #[serde(default = "default_true")]
        avoid_ambiguous: bool,
    },
    Words {
        count: usize,
        separator: String,
        #[serde(default)]
        capitalize: bool,
        #[serde(default = "default_true")]
        include_number: bool,
    },
    Pin {
        length: usize,
    },
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn random_index(upper: usize) -> usize {
    debug_assert!(upper > 0 && upper <= 256);
    let zone = 256 - (256 % upper);
    loop {
        let mut byte = [0_u8; 1];
        rand::rng().fill_bytes(&mut byte);
        if usize::from(byte[0]) < zone {
            return usize::from(byte[0]) % upper;
        }
    }
}

pub(crate) fn shuffle(bytes: &mut [u8]) {
    for index in (1..bytes.len()).rev() {
        bytes.swap(index, random_index(index + 1));
    }
}

pub fn generate_password_with_recipe(recipe: &PasswordRecipe) -> Result<String> {
    match recipe {
        PasswordRecipe::Random {
            length,
            uppercase,
            lowercase,
            numbers,
            symbols,
            avoid_ambiguous,
        } => {
            if !(8..=256).contains(length) {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "random password length must be 8..=256".into(),
                });
            }
            let classes: Vec<&[u8]> = [
                uppercase.then_some(if *avoid_ambiguous {
                    b"ABCDEFGHJKLMNPQRSTUVWXYZ".as_slice()
                } else {
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice()
                }),
                lowercase.then_some(if *avoid_ambiguous {
                    b"abcdefghijkmnopqrstuvwxyz".as_slice()
                } else {
                    b"abcdefghijklmnopqrstuvwxyz".as_slice()
                }),
                numbers.then_some(if *avoid_ambiguous {
                    b"23456789".as_slice()
                } else {
                    b"0123456789".as_slice()
                }),
                symbols.then_some(b"!@#$%^&*()-_=+".as_slice()),
            ]
            .into_iter()
            .flatten()
            .collect();
            if classes.is_empty() || *length < classes.len() {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "select at least one character class".into(),
                });
            }
            let pool: Vec<u8> = classes
                .iter()
                .flat_map(|value| value.iter().copied())
                .collect();
            let mut output: Vec<u8> = classes
                .iter()
                .map(|class| class[random_index(class.len())])
                .collect();
            while output.len() < *length {
                output.push(pool[random_index(pool.len())]);
            }
            shuffle(&mut output);
            String::from_utf8(output).map_err(|_| KeyLeaseError::Storage)
        }
        PasswordRecipe::Words {
            count,
            separator,
            capitalize,
            include_number,
        } => {
            if !(3..=12).contains(count)
                || separator.chars().count() > 3
                || separator.chars().any(char::is_control)
            {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "word password must use 3..=12 words and a short separator".into(),
                });
            }
            // Combining two independently selected 6-bit halves gives each
            // readable word 12 bits of entropy without shipping a huge wordlist.
            const PREFIXES: [&str; 64] = [
                "amber", "ancient", "apricot", "arctic", "autumn", "azure", "brave", "bright",
                "calm", "cedar", "clever", "cloud", "coral", "cosmic", "crimson", "crystal",
                "daring", "delta", "eager", "ember", "emerald", "fable", "fair", "forest",
                "gentle", "golden", "grand", "green", "happy", "hidden", "indigo", "ivory", "jade",
                "jolly", "kind", "lively", "lucky", "lunar", "maple", "merry", "misty", "modern",
                "navy", "nimble", "noble", "ocean", "olive", "orange", "pearl", "polar", "proud",
                "quiet", "rapid", "red", "royal", "silver", "solar", "steady", "swift", "tender",
                "vivid", "warm", "wild", "young",
            ];
            const SUFFIXES: [&str; 64] = [
                "anchor", "apple", "badger", "beacon", "birch", "breeze", "bridge", "canyon",
                "castle", "comet", "coral", "dawn", "dolphin", "dragon", "eagle", "falcon", "fern",
                "field", "finch", "flame", "flower", "fox", "garden", "glade", "grove", "harbor",
                "hawk", "hill", "island", "lake", "lantern", "leaf", "lion", "meadow", "meteor",
                "moon", "oak", "otter", "owl", "panda", "pine", "planet", "plum", "pond", "quartz",
                "rain", "raven", "reef", "river", "robin", "rock", "rose", "sail", "sky",
                "sparrow", "star", "stone", "storm", "sun", "tiger", "trail", "valley", "wave",
                "willow",
            ];
            let mut words = Vec::with_capacity(*count);
            for _ in 0..*count {
                let mut word = format!(
                    "{}{}",
                    PREFIXES[random_index(PREFIXES.len())],
                    SUFFIXES[random_index(SUFFIXES.len())]
                );
                if *capitalize {
                    word.get_mut(0..1)
                        .expect("ASCII word")
                        .make_ascii_uppercase();
                }
                words.push(word);
            }
            if *include_number {
                let index = random_index(words.len());
                words[index].push_str(&format!("{:02}", random_index(100)));
            }
            Ok(words.join(separator))
        }
        PasswordRecipe::Pin { length } => {
            if !(4..=20).contains(length) {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "PIN length must be 4..=20".into(),
                });
            }
            Ok((0..*length)
                .map(|_| char::from(b'0' + random_index(10) as u8))
                .collect())
        }
    }
}
pub fn current_totp(config: &TotpConfig) -> Result<(String, u64)> {
    let algorithm = match config.algorithm {
        TotpAlgorithm::Sha1 => totp_rs::Algorithm::SHA1,
        TotpAlgorithm::Sha256 => totp_rs::Algorithm::SHA256,
        TotpAlgorithm::Sha512 => totp_rs::Algorithm::SHA512,
    };
    let secret = validated_totp_secret(config)?;
    // Some long-lived KeePass and authenticator entries use secrets shorter
    // than RFC 4226's current 128-bit recommendation. They are already in
    // active use and generate interoperable codes, so accept them on import
    // while retaining structural validation above.
    let totp = totp_rs::TOTP::new_unchecked(
        algorithm,
        config.digits as usize,
        1,
        config.period,
        secret,
        config.issuer.clone(),
        config.account.clone().unwrap_or_default(),
    );
    let now = Utc::now().timestamp() as u64;
    let code = totp.generate(now);
    Ok((code, config.period - (now % config.period)))
}
