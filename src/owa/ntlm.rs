use base64::prelude::*;
use std::error::Error;

#[derive(Debug)]
pub struct NTLM;

impl NTLM {
    pub fn parse_domain(ntlm_response: &str) -> Result<String, Box<dyn Error>> {
        let raw = BASE64_STANDARD.decode(ntlm_response).expect("Not a base64 encoded string");
        let target_name_len = u16::from_le_bytes([raw[12], raw[13]]) as usize;
        let target_name_offset = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]) as usize;
        let target_name_bytes = &raw[target_name_offset..target_name_offset + target_name_len];
        if target_name_len > 0 && raw.len() >= target_name_offset + target_name_len {
            if let Ok(target_name) = String::from_utf16(
                                &target_name_bytes
                                    .chunks(2)
                                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                                    .collect::<Vec<_>>(),) {
                return Ok(target_name);
            } else {
                return Err("Could not find domain name".into());
            }
        }
        Err("Error in challenge".into())
    }
}