use std::collections::HashMap;

#[derive(Debug, Clone)]
struct Live {
    username: String,
    echo: String,
}

#[derive(Debug, Default)]
pub struct Sessions {
    multi: bool,
    by_id: HashMap<String, Live>,
    primary: HashMap<String, String>,
}

impl Sessions {
    pub fn set_multi(&mut self, multi: bool) {
        self.multi = multi;
    }

    pub fn multi(&self) -> bool {
        self.multi
    }

    pub fn register_api(&mut self, username: &str, token: &str) {
        let username = username.to_ascii_lowercase();
        self.by_id.insert(
            token.to_string(),
            Live {
                username: username.clone(),
                echo: token.to_string(),
            },
        );
        if !self.multi {
            self.primary.insert(username, token.to_string());
        }
    }

    pub fn username_for(&self, token: &str) -> Option<String> {
        self.by_id.get(token).map(|live| live.username.clone())
    }

    pub fn api_alive(&self, token: &str) -> bool {
        let Some(live) = self.by_id.get(token) else {
            return false;
        };
        if self.multi {
            return true;
        }
        self.primary
            .get(&live.username)
            .map(|id| id == token)
            .unwrap_or(false)
    }

    pub fn compat_register(&mut self, username: &str, value: &str, is_alive: &str) {
        let username = username.trim().to_ascii_lowercase();
        let uva = format!("{username}:{value}:{is_alive}");
        self.by_id.insert(
            uva.clone(),
            Live {
                username: username.clone(),
                echo: value.to_string(),
            },
        );
        if !self.multi {
            self.primary.insert(username, uva);
        }
    }

    /// Echo the session value, or `"0"` when this window is no longer primary.
    pub fn compat_echo(&mut self, uva: &str) -> String {
        let mut parts = uva.splitn(3, ':');
        let username = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let value = parts.next().unwrap_or("").to_string();
        if self.multi {
            if let Some(live) = self.by_id.get(uva) {
                return live.echo.clone();
            }
            self.by_id.insert(
                uva.to_string(),
                Live {
                    username,
                    echo: value.clone(),
                },
            );
            return value;
        }
        match self.primary.get(&username) {
            Some(primary) if primary == uva => self
                .by_id
                .get(uva)
                .map(|live| live.echo.clone())
                .unwrap_or(value),
            Some(_) => "0".to_string(),
            None => {
                self.primary.insert(username.clone(), uva.to_string());
                self.by_id.insert(
                    uva.to_string(),
                    Live {
                        username,
                        echo: value.clone(),
                    },
                );
                value
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_login_kicks_the_older_window() {
        let mut sessions = Sessions::default();
        sessions.compat_register("ada", "11", "1");
        sessions.register_api("ada", "token-b");
        assert!(!sessions.api_alive("missing"));
        assert!(sessions.api_alive("token-b"));
        assert_eq!(sessions.compat_echo("ada:11:1"), "0");
    }

    #[test]
    fn multi_screen_keeps_both() {
        let mut sessions = Sessions::default();
        sessions.set_multi(true);
        sessions.compat_register("ada", "11", "1");
        sessions.register_api("ada", "token-b");
        assert!(sessions.api_alive("token-b"));
        assert_eq!(sessions.compat_echo("ada:11:1"), "11");
    }
}
