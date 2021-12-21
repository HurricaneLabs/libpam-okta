use dialoguer::{Input, Password};
use pam_okta::{SUPPORTED_FACTORS, verify_first_factor, verify_second_factor};
use std::env;
use whoami;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("Usage: {} <okta_tenant>", args[0]);
        return
    }

    let mut okta_tenant = String::from(&args[1]);

    if !okta_tenant.contains(".") {
        okta_tenant.push_str(".okta.com");
    }

    let username = Input::new()
        .with_prompt("Okta username")
        .default(whoami::username())
        .interact_text()
        .unwrap_or("".to_string());
    let password = Password::new()
        .with_prompt("Okta password")
        .interact()
        .unwrap_or("".to_string());

    if username.is_empty() || password.is_empty() {
        return;
    }

    let resp_json: serde_json::Value = match verify_first_factor(&okta_tenant, &username, &password) {
        Ok(response) => match response.into_json() {
            Ok(result) => result,
            Err(_) => {
                println!("Authentication succeeded but received invalid response from Okta!");
                return;
            }
        },
        Err(ureq::Error::Status(code, response)) => {
            println!("{}: {}", code, response.into_string().unwrap_or(String::from("")));
            return;
        },
        Err(_) => {
            println!("Authentication failed!");
            return;
        }
    };

    let resp_status = resp_json["status"].as_str().unwrap_or("");

    if resp_status == "SUCCESS" {
        println!("No MFA required, cannot select factor");
        return;
    } else if resp_status != "MFA_REQUIRED" {
        println!("Authentication succeeded, but got an unexpected status {}", resp_status);
        return;
    }

    // Verify second factor
    let mut factors: Vec<&serde_json::Value> = Vec::new();

    match resp_json["_embedded"]["factors"].as_array() {
        Some(arr) => {
            for factor in arr {
                let factor_provider: &str = factor["provider"].as_str().unwrap_or("");
                let factor_type: &str = factor["factorType"].as_str().unwrap_or("");

                if SUPPORTED_FACTORS.contains(&(factor_type, factor_provider)) {
                    factors.push(factor);
                }
            }
        },
        None => {
            println!("Could not decode factors in response");
            return;
        },
    };

    let state_token: &str = match resp_json["stateToken"].as_str() {
        Some(val) => val,
        None => {
            println!("Could not decode stateToken in response");
            return;
        },
    };

    loop {
        let mut idx = 1;

        println!("Available MFA options:");
        for factor in &factors {
            let factor_provider: &str = factor["provider"].as_str().unwrap_or("");
            let factor_type: &str = factor["factorType"].as_str().unwrap_or("");

            if idx == 1 {
                println!("{}) {} provided by {} (DEFAULT)", idx, factor_type, factor_provider);
                println!("---");
            } else {
                println!("{}) {} provided by {}", idx, factor_type, factor_provider);
            }

            idx += 1;
        }
        println!("---");
        println!("Q) Quit");
        println!("");

        let mut choice: String = Input::new()
            .with_prompt("Select an option: ")
            .default(String::from("Q"))
            .interact_text()
            .unwrap_or(String::from("Q"));

        choice.make_ascii_lowercase();

        if choice.as_str() == "q" {
            break;
        }

        let choice: i32 = choice.parse().unwrap_or(-1) - 1;

        if choice < 0 || choice as usize >= factors.len() {
            println!("Invalid choice!");
            continue;
        }

        let factor = match factors.get(choice as usize) {
            Some(value) => value,
            None => {
                println!("Invalid choice!");
                continue;
            }
        };

        let prompt_func = |prompt: &str, response: bool| -> Option<String> {
            if response {
                // Need to prompt for info
                return Some(Password::new()
                    .with_prompt(prompt)
                    .interact()
                    .unwrap_or(String::from("")));
            } else {
                // Just output some text
                println!("{}", prompt);
                return None;
            }
        };

        match verify_second_factor(factor, state_token, prompt_func) {
            Some(true) => {
                println!("Success");
                break;
            },
            Some(false) | None => {
                println!("Failed, please try again.")
            },
        }
    }
}
