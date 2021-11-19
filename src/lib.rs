use pamsm::{
    pam_module,
    Pam,
    PamFlags,
    PamError,
    PamLibExt,
    PamMsgStyle,
    PamServiceModule
};
use serde_json;
use std::collections::HashMap;
use std::ffi::CString;
use std::thread::sleep;
use std::time::{Duration, Instant};
use ureq;

struct PamOkta;

fn verify_first_factor(okta_tenant: &str, username: &str, password: &str) -> Result<ureq::Response, ureq::Error> {
    let authn_url = format!("https://{}/api/v1/authn", okta_tenant);

    // println!("Authn URL: {}", authn_url);
    // println!(
    //     "Username: {}, Password: '{}'",
    //     username,
    //     password,
    // );

    ureq::post(authn_url.as_str())
        .set("accept", "application/json")
        .send_json(ureq::json!({
            "username": username,
            "password": password,
            "options": {
                "multiOptionalFactorEnroll": false,
                "warnBeforePasswordExpired": false
            }
        }))
}

fn verify_second_factor(pamh: &Pam, factor: &serde_json::Value, state_token: &str) -> Option<bool> {
    const SUPPORTED_FACTORS: [(&str, &str); 6] = [
        ("push", "OKTA"),
        ("token:software:totp", "OKTA"),
        ("token:software:totp", "GOOGLE"),
        ("token:hardware", "YUBICO"),
        ("call", "OKTA"),
        ("sms", "OKTA"),
    ];

    // let factor_id: &str = factor["id"].as_str().unwrap_or("");
    let factor_provider: &str = factor["provider"].as_str().unwrap_or("");
    let factor_type: &str = factor["factorType"].as_str().unwrap_or("");
    let factor_verify_url: &str = factor["_links"]["verify"]["href"].as_str().unwrap_or("");

    if !SUPPORTED_FACTORS.contains(&(factor_type, factor_provider)) {
        return None;
    }

    // println!("Trying {} factor provided by {}", factor_type, factor_provider);

    let mut factor_data = HashMap::from([
        ("stateToken", state_token)
    ]);

    let now = Instant::now();

    while now.elapsed().as_millis() <= 30000 {
        let resp_json: serde_json::Value = match ureq::post(&factor_verify_url)
            .set("accept", "application/json")
            .send_json(ureq::json!(factor_data)) {
                Ok(response) => match response.into_json() {
                    Ok(result) => result,
                    Err(_) => return None
                },
                Err(_) => return Some(false)
            };

        let status = resp_json["status"].as_str().unwrap_or("");
        let factor_result = resp_json["factorResult"].as_str().unwrap_or("");

        if status == "SUCCESS" {
            return Some(true);
        } else if factor_result == "CHALLENGE" {
            match (factor_type, factor_provider) {
                // ("push", "OKTA") => {},
                ("token:software:totp", "OKTA") | ("token:software:totp", "GOOGLE") => {
                    let prompt = format!("{} 6-digit PIN: ", factor_provider);

                    match pamh.conv(Some(prompt.as_str()), PamMsgStyle::PROMPT_ECHO_OFF) {
                        Ok(Some(code)) => {
                            let pass_code = code.to_str().unwrap_or("");
                            if pass_code.is_empty() {
                                return None
                            }
                            factor_data.insert("passCode", pass_code);
                        },
                        Ok(_) | Err(_) => return None,
                    }
                },
                // ("token:software:totp", "GOOGLE") => {},
                ("token:hardware", "YUBICO") => {
                    match pamh.conv(Some("Please press your Yubikey."), PamMsgStyle::PROMPT_ECHO_OFF) {
                        Ok(Some(code)) => {
                            let pass_code = code.to_str().unwrap_or("");
                            if pass_code.is_empty() {
                                return None
                            }
                            factor_data.insert("passCode", pass_code);
                        },
                        Ok(_) | Err(_) => return None,
                    }
                },
                ("call", "OKTA") | ("sms", "OKTA") => {
                    let prompt = format!("Verification code received via {}: ", factor_type);

                    match pamh.conv(Some(prompt.as_str()), PamMsgStyle::PROMPT_ECHO_OFF) {
                        Ok(Some(code)) => {
                            let pass_code = code.to_str().unwrap_or("");
                            if pass_code.is_empty() {
                                return None
                            }
                            factor_data.insert("passCode", pass_code);
                        },
                        Ok(_) | Err(_) => return None,
                    }
                },
                (_, _) => {
                    println!("Received unexpected CHALLENGE result");
                    return None;
                }
            }
        } else if factor_result != "WAITING" {
            println!("Received unexpected factorResult {}", factor_result);
            return None;
        }

        sleep(Duration::from_secs(1));
    };

    None
}

fn verify_device_grant(okta_tenant: &str,
                       okta_client_id: &str) -> Option<String> {

    let now = Instant::now();

    let authorize_url = format!("https://{}/oauth2/v1/device/authorize", okta_tenant);

    let resp_json: serde_json::Value = match ureq::post(authorize_url.as_str())
        .set("accept", "application/json")
        .send_form(&[
            ("client_id", okta_client_id),
            ("scope", "openid profile groups"),
        ]) {
            Ok(response) => match response.into_json() {
                Ok(result) => result,
                Err(_) => {
                    // println!("Success obtaining device code, but failure decoding response");
                    return None;
                }
            },
            Err(ureq::Error::Status(_code, _response)) => {
                // println!("{}: {}", code, response.into_string().unwrap_or(String::from("")));
                return None;
            },
            Err(_) => {
                // println!("Failed to obtain device code");
                return None;
            }
        };

    let device_code = match resp_json["device_code"].as_str() {
        Some(val) => val,
        None => return None,
    };

    let expires_in = match resp_json["expires_in"].as_u64() {
        Some(val) => val,
        None => return None,
    };

    let verify_url = match resp_json["verification_uri_complete"].as_str() {
        Some(val) => val,
        None => return None,
    };

    let interval = match resp_json["interval"].as_u64() {
        Some(val) => val,
        None => 5
    };

    println!("Open {} in your browser and continue authentication there", verify_url);

    let mut access_token = String::from("");

    let token_url = format!("https://{}/oauth2/v1/token", okta_tenant);

    while now.elapsed().as_secs() < expires_in {

        let resp_json: serde_json::Value = match ureq::post(token_url.as_str())
            .set("accept", "application/json")
            .send_form(&[
                ("client_id", okta_client_id),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
            ]) {
                Ok(response) => match response.into_json() {
                    Ok(result) => result,
                    Err(_) => {
                        // println!("Success obtaining access token, but failure decoding response");
                        return None;
                    }
                },
                Err(ureq::Error::Status(code, response)) => {
                    if code == 400 {
                        match response.into_json() {
                            Ok(result) => result,
                            Err(_) => {
                                // println!("{}: failed to decode response", code);
                                return None;
                            }
                        }
                    } else {
                        println!("{}: {}", code, response.into_string().unwrap_or(String::from("")));
                        return None;
                    }
                },
                Err(_) => {
                    // println!("Failed to obtain access token");
                    return None;
                }
            };

        if resp_json["error"].as_str().unwrap_or("") != "authorization_pending" {
            if resp_json["token_type"].as_str().unwrap_or("") == "" {
                // println!("token_type not found in response");
                return None
            }

            match resp_json["access_token"].as_str() {
                Some(val) => {
                    access_token.push_str(val);
                    break;
                },
                None => {
                    // println!("Unable to get access_key from response");
                    return None;
                }
            }
        }

        sleep(Duration::from_secs(interval));
    }

    let auth_header = format!("Bearer {}", access_token);
    let userinfo_url = format!("https://{}/oauth2/v1/userinfo", okta_tenant);

    let resp_json: serde_json::Value = match ureq::get(userinfo_url.as_str())
        .set("authorization", &auth_header)
        .call() {
            Ok(response) => match response.into_json() {
                Ok(result) => result,
                Err(_) => return None
            },
            Err(_) => return None,
        };

    // println!(
    //     "Logged in as {} ({})",
    //     resp_json["name"].as_str().unwrap_or("unknown"),
    //     resp_json["preferred_username"].as_str().unwrap_or("unknown"),
    // );

    let logged_in_user = match resp_json["preferred_username"].as_str() {
        Some(val) => String::from(val),
        None => return None
    };

    Some(logged_in_user)
}

impl PamServiceModule for PamOkta {
    fn authenticate(pamh: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        // Parse args
        let mut okta_tenant = String::from("");
        let mut okta_client_id = String::from("");
        let mut username_suffix = String::from("");
        let mut check_username_prefix = false;

        for arg in args {
            // println!("Got arg: {}", arg);

            match arg.split_once("=") {
                Some((argname, argvalue)) => {
                    let mut argname = String::from(argname);
                    argname.make_ascii_lowercase();

                    match argname.as_str() {
                        "tenant" => {
                            /*
                                TODO: Should the tenant setting be validated?
                                In order to exploit a lack of validation, you'd
                                have to be root on the system already, and at
                                that point you could easily replace the PAM
                                stack anyways.
                            */
                            okta_tenant.push_str(argvalue)
                        },
                        "client_id" => okta_client_id.push_str(argvalue),
                        "username_suffix" => username_suffix.push_str(argvalue),
                        _ => {},
                    }
                },
                None => {
                    let mut argname = String::from(arg);
                    argname.make_ascii_lowercase();

                    match argname.as_str() {
                        "check_username_prefix" => {
                            check_username_prefix = true;
                        },
                        _ => {},
                    }
                }
            }
        }

        if okta_tenant.is_empty() {
            //println!("No Okta tenant specified");
            return PamError::AUTHINFO_UNAVAIL;
        }

        // If okta_tenant is not fully qualified, default to .okta.com
        if !okta_tenant.contains(".") {
            okta_tenant.push_str(".okta.com");
        }

        // Determine username
        let username = match pamh.get_user(Some("Username: ")) {
            Ok(Some(user)) => user.to_str().unwrap_or(""),
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };
        // Get password
        let password = match pamh.get_authtok(Some("Password: ")) {
            Ok(Some(pass)) => pass.to_str().unwrap_or(""),
            Ok(None) => "",
            Err(e) => return e,
        };

        let okta_tenant = okta_tenant.as_str();
        let okta_client_id = okta_client_id.as_str();

        if password == "" && !okta_client_id.is_empty() {
            let mut valid_usernames: Vec<&str> = vec!(username);
            let mut username_with_suffix = String::from("");

            if !username_suffix.is_empty() {
                username_with_suffix.push_str(format!("{}@{}", username, username_suffix).as_str());
                valid_usernames.push(username_with_suffix.as_str());
            }

            match verify_device_grant(okta_tenant, okta_client_id) {
                Some(logged_in_user) => {
                    let mut logged_in_user_forms: Vec<&str> = vec!(&logged_in_user);

                    if check_username_prefix {
                        match logged_in_user.split_once("@") {
                            Some((username_prefix, _)) => {
                                logged_in_user_forms.push(username_prefix);
                            },
                            None => {},
                        }
                    }

                    // println!("Valid users: {:?}", valid_usernames);

                    for logged_in_user_form in logged_in_user_forms {
                        // println!("Checking to see if {} is valid", logged_in_user_form);
                        if valid_usernames.contains(&logged_in_user_form) {
                            // println!("Valid!");
                            return PamError::SUCCESS;
                        }
                    }

                    return PamError::AUTH_ERR;
                },
                None => return PamError::AUTHINFO_UNAVAIL,
            }
        } else {
            let password = String::from(password);
            let authtok = password.clone();

            match CString::new(authtok) {
                Ok(val) => {
                    let _ = pamh.set_authtok(&val);
                },
                Err(_) => {},
            };
            let resp_json: serde_json::Value = match verify_first_factor(okta_tenant, username, password.as_str()) {
                Ok(response) => match response.into_json() {
                    Ok(result) => result,
                    Err(_) => {
                        // println!("First factor success, but failed to decode response");
                        return PamError::AUTHINFO_UNAVAIL;
                    }
                },
                Err(ureq::Error::Status(_code, _response)) => {
                    // println!("{}: {}", code, response.into_string().unwrap_or(String::from("")));
                    return PamError::AUTHINFO_UNAVAIL;
                },
                Err(_) => {
                    // println!("First factor failed");
                    return PamError::AUTHINFO_UNAVAIL;
                }
            };

            let resp_status = match resp_json["status"].as_str() {
                Some(val) => val,
                None => {
                    // println!("Malformed response, missing 'status'");
                    return PamError::AUTHINFO_UNAVAIL;
                }
            };

            if resp_status == "SUCCESS" {
                return PamError::SUCCESS;
            } else if resp_status != "MFA_REQUIRED" {
                // println!("Got unexpected status {}", resp_status);
                return PamError::AUTH_ERR
            }

            // Verify second factor
            let factors = match resp_json["_embedded"]["factors"].as_array() {
                Some(arr) => arr,
                None => {
                    // println!("Could not decode factors in response");
                    return PamError::AUTHINFO_UNAVAIL;
                },
            };

            let state_token: &str = match resp_json["stateToken"].as_str() {
                Some(val) => val,
                None => {
                    // println!("Could not decode stateToken in response");
                    return PamError::AUTHINFO_UNAVAIL;
                },
            };

            for factor in factors {
                match verify_second_factor(&pamh, factor, state_token) {
                    Some(true) => return PamError::SUCCESS,
                    Some(false) => return PamError::AUTH_ERR,
                    None => {}
                }
            }
        }

        PamError::AUTHINFO_UNAVAIL
    }
}

pam_module!(PamOkta);
