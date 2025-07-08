use reqwest::blocking::{Client};
use reqwest::header;
use std::error::Error;
use owa_enum::{Color, err, log, msg};
use base64::prelude::*;

const OWA_ENDPOINTS: [&str; 5] = ["/ews",
                                  "/autodiscover/autodiscover.xml",
                                  "/rpc",
                                  "/mapi",
                                  "/oab"];
const OWA_LOGIN: &str = "/owa/auth.owa";

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

#[derive(Debug)]
pub enum OwaResult {
    UserNotFound,
    UserExists,
    PasswordValid,
}

#[derive(Debug)]
pub struct Owa {
    uri: String,
    domain: String,
    http_client: Client
}

impl Owa {
    pub fn new(http_client: Client, uri: String, domain: Option<String>) -> Self {
        Self {
            uri: uri,
            domain: domain.unwrap_or("".to_string()),
            http_client: http_client
        }
    }

    pub fn get_domain(&self) -> String {
        self.domain.clone()
    }

    pub fn user_exists(&self, user: &str, password: &str) -> OwaResult {
        let login_data = [
                          ("destination", format!("{}{}", self.uri, "/owa")),
                          ("flags", "4".to_string()),
                          ("forcedownlevel", "0".to_string()),
                          ("username", format!("{}\\{}", self.domain, user)),
                          ("password", password.to_string()),
                          ("passwordText", "".to_string()),
                          ("isUtf8", "1".to_string())
                         ];

        match self.http_client.post(format!("{}{}", self.uri, OWA_LOGIN))
                              .form(&login_data)
                              .send()
        {
            Ok(res) => {
                if let Some(location) = res.headers().get("Location") {
                    if location.to_str().unwrap_or("").contains("extEmail=") {
                        return OwaResult::PasswordValid;
                    }
                }
                return OwaResult::UserExists;
            }
            Err(e) => {
                if e.is_timeout(){
                    return OwaResult::UserNotFound;
                } else if e.is_redirect(){
                    return OwaResult::UserExists;
                } else {
                    log!("Got {:?}", e);
                    return OwaResult::UserExists;
                }
            }
        }
    }

    fn get_endpoint_url(&self) -> Result<&str, &str> {
        for endpoint in OWA_ENDPOINTS {
            let url = format!("{}{}", self.uri, endpoint);
            match self.http_client.get(&url).send(){
                Ok(response) => {
                    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                        return Ok(endpoint);
                    }
                }
                Err(e) => {}
            }
        }
        Err("No endpoint found")
    }

    pub fn get_domain_name(&mut self) -> Result<(), Box<dyn Error>> {
        if self.domain != "" {
            return Ok(());
        }
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION,
                       header::HeaderValue::from_static("NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="));

        if let Ok(endpoint) = self.get_endpoint_url() {
            let url = format!("{}{}", self.uri.clone(), endpoint);
            msg!("Endpoint used: {}", Color::wrap(&url, Color::CYAN));
            match self.http_client.get(url).headers(headers).send() {
                Ok(res) => {
                        if let Some(ntlm_response) = res.headers()
                                                        .get("WWW-Authenticate")
                                                        .expect("No WWW-Authenticate header")
                                                        .to_str()?
                                                        .strip_prefix("NTLM "){
                            match NTLM::parse_domain(ntlm_response){
                                Ok(domain) => {
                                    self.domain = domain;
                                    return Ok(());
                                }
                                Err(e) => {return Err(e);}
                            }
                        }
                        return Err("Cannot find domain name in response".into());
                    }
               Err(e) => return Err(format!("Http client error: {}", e).into()),
            }
        }
        Err("No NTLM authent found".into())
    }
}
