use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Config {
    pub secret: String,
}

impl Config {
    pub fn new(args: &[String]) -> Result<Config, &'static str> {
        if args.len() != 2 {
            return Err("A single base 32 encoded secret is required");
        }
        let secret = args[1].clone();
        return Ok(Config { secret });
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let duration_from_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let seconds_from_epoch = duration_from_epoch.as_secs();
    let counter = totp::calculate_counter(seconds_from_epoch, 0,30);
    let secret = totp::hex::base_32_to_hex(&config.secret)?;
    let code = totp::calculate_totp_value(&secret, &counter, 6)?;

    println!("calculated TOTP wth result {}", code);
    Ok(())
}

pub mod totp {
    use crypto::hmac::Hmac;
    use crypto::mac::Mac;
    use crypto::sha1::Sha1;

    pub fn calculate_counter(seconds_from_relative_epoc: u64,
                             t0: u64,
                             duration_seconds: u32) -> String {
        let counter = (seconds_from_relative_epoc - t0) / duration_seconds as u64;

        format!("{:016X}", counter)
    }

    pub fn calculate_totp_value(secret_key: &str, counter: &str, desired_pin_length: u8) -> Result<String, String> {
        let secret_key_as_hex = self::hex::hex_to_bytes(secret_key)?;
        let counter_as_hex = self::hex::hex_to_bytes(counter)?;
        let code_bytes = calculate_hmac(&secret_key_as_hex, &counter_as_hex);
        let index = extract_four_least_sig_digits(&code_bytes);
        let extracted_code = extract_code(&code_bytes, index) as u64;
        let code_of_length = extracted_code % 10_u64.pow(desired_pin_length as u32);
        let padded_code = format!("{:01$}", code_of_length, desired_pin_length as usize);

        Ok(padded_code)
    }

    pub fn calculate_hmac(secret_key: &Vec<u8>, counter: &Vec<u8>) -> Vec<u8>  {
        let mut mac = Hmac::new(Sha1::new(), secret_key);
        mac.input(counter);
        let result = mac.result();
        let code = result.code();
        code.to_vec()
    }

    pub fn extract_code(code: &Vec<u8>, offset: u8) -> u32 {
        let byte_offset = offset as usize;
        let bytes: [u8;4] = [code[byte_offset] & 0x7f, code[byte_offset + 1], code[byte_offset + 2], code[byte_offset + 3]];
        u32::from_be_bytes(bytes)
    }

    pub fn extract_four_least_sig_digits(input: &[u8]) -> u8 {
        input[input.len() - 1] & 0xf
    }

    pub mod hex {
        use base32::Alphabet;

        pub fn base_32_to_hex(input: &str) -> Result<String, String> {
            base32::decode(Alphabet::RFC4648{padding: false},input)
                .map(|bytes| hex::encode(bytes))
                .ok_or("Failed to base 32 decode input to a hex string".to_string())
        }

        pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>, String> {
            hex::decode(input).map_err(|e| format!("Failed to convert input bytes: {}", e))
        }
    }
}

#[cfg(test)]
mod totp_tests {
    use super::totp;

    #[test]
    fn test_basic_counter() {
        assert_eq!("0000000000000002", totp::calculate_counter(60, 0, 30));
    }

    #[test]
    fn test_basic_counter_rounds_correctly() {
        assert_eq!("0000000000000001", totp::calculate_counter(59, 0, 30));
    }

    #[test]
    fn test_extract_least_sig() {
        let bytes: [u8; 20] = [0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a];
        assert_eq!(0xa, totp::extract_four_least_sig_digits(&bytes));
    }

    #[test]
    fn test_extract_code() {
        let bytes: Vec<u8> = vec!(0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a);
        assert_eq!(0x50ef7f19, totp::extract_code(&bytes, 10))
    }

    #[test]
    fn test_totp_generation() {
        let secret = "3132333435363738393031323334353637383930";
        let t = totp::calculate_counter(59, 0, 30);
        assert_eq!("94287082", totp::calculate_totp_value(&secret, &t, 8));
    }
}

#[cfg(test)]
mod hex_tests {
    use crate::totp;

    #[test]
    fn test_base_32_to_hex_string() {
        assert_eq!("3132333435363738393031323334353637383930", totp::hex::base_32_to_hex("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap());
    }

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(vec!(52, 33), totp::hex::hex_to_bytes("3421"));
        assert_eq!(vec!(4, 33), totp::hex::hex_to_bytes("0421"));
    }
}

