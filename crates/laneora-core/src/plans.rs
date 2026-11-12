use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub struct Plan {
    pub id: &'static str,
    pub label: &'static str,
    pub seconds: i64,
}

pub const PLANS: &[Plan] = &[
    Plan {
        id: "trial_1h",
        label: "Trial — 1 hour",
        seconds: 3600,
    },
    Plan {
        id: "day_1",
        label: "1 day",
        seconds: 86_400,
    },
    Plan {
        id: "week_1",
        label: "1 week",
        seconds: 7 * 86_400,
    },
    Plan {
        id: "days_15",
        label: "15 days",
        seconds: 15 * 86_400,
    },
    Plan {
        id: "month_1",
        label: "1 month",
        seconds: 30 * 86_400,
    },
    Plan {
        id: "months_3",
        label: "3 months",
        seconds: 90 * 86_400,
    },
    Plan {
        id: "months_6",
        label: "6 months",
        seconds: 180 * 86_400,
    },
    Plan {
        id: "year_1",
        label: "1 year",
        seconds: 365 * 86_400,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Active,
    Expired,
    Disabled,
    Unset,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Disabled => "disabled",
            Self::Unset => "unset",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanInfo {
    pub id: &'static str,
    pub label: &'static str,
}

pub fn plan_catalog() -> Vec<PlanInfo> {
    PLANS
        .iter()
        .map(|plan| PlanInfo {
            id: plan.id,
            label: plan.label,
        })
        .collect()
}

pub fn plan_by_id(id: &str) -> Option<&'static Plan> {
    PLANS.iter().find(|plan| plan.id == id.trim())
}

pub fn account_status(
    active: bool,
    subscription_end: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> AccountStatus {
    if !active {
        return AccountStatus::Disabled;
    }
    match subscription_end {
        None => AccountStatus::Unset,
        Some(end) if end <= now => AccountStatus::Expired,
        Some(_) => AccountStatus::Active,
    }
}

pub fn denial_message(
    status: AccountStatus,
    plan_label: Option<&str>,
    subscription_end: Option<&str>,
) -> Option<(&'static str, String)> {
    match status {
        AccountStatus::Disabled => Some((
            "disabled",
            "This account is disabled. Ask your admin.".to_string(),
        )),
        AccountStatus::Expired => {
            let label = plan_label.unwrap_or("Subscription");
            let end = subscription_end.unwrap_or("");
            Some((
                "expired",
                format!("{label} ended {end}. Ask your admin to renew."),
            ))
        }
        AccountStatus::Active | AccountStatus::Unset => None,
    }
}

#[derive(Debug, Clone)]
pub struct AppliedPlan {
    pub id: String,
    pub label: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

pub fn apply_plan(
    plan_id: &str,
    current_start: Option<DateTime<Utc>>,
    current_end: Option<DateTime<Utc>>,
    extend: bool,
    now: DateTime<Utc>,
) -> Result<AppliedPlan, String> {
    let plan = plan_by_id(plan_id).ok_or_else(|| {
        let known = PLANS
            .iter()
            .map(|plan| plan.id)
            .collect::<Vec<_>>()
            .join(", ");
        format!("Unknown plan '{plan_id}'. Use one of: {known}")
    })?;
    let delta = Duration::seconds(plan.seconds);
    let (start, end) = if extend {
        if let Some(end) = current_end.filter(|end| *end > now) {
            (current_start.unwrap_or(now), end + delta)
        } else {
            (now, now + delta)
        }
    } else {
        (now, now + delta)
    };
    Ok(AppliedPlan {
        id: plan.id.to_string(),
        label: plan.label.to_string(),
        start,
        end,
    })
}

pub fn format_utc(moment: DateTime<Utc>) -> String {
    moment.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn parse_utc(value: &str) -> Option<DateTime<Utc>> {
    let text = value.trim();
    if text.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|moment| moment.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn unset_account_can_log_in() {
        assert_eq!(account_status(true, None, now()), AccountStatus::Unset);
        assert!(denial_message(AccountStatus::Unset, None, None).is_none());
    }

    #[test]
    fn expired_and_disabled_are_denied() {
        let end = now() - Duration::seconds(1);
        assert_eq!(
            account_status(true, Some(end), now()),
            AccountStatus::Expired
        );
        assert_eq!(account_status(false, None, now()), AccountStatus::Disabled);
    }

    #[test]
    fn extend_adds_onto_remaining_time() {
        let start = now() - Duration::days(1);
        let end = now() + Duration::hours(2);
        let applied = apply_plan("trial_1h", Some(start), Some(end), true, now()).unwrap();
        assert_eq!(applied.end, end + Duration::hours(1));
        assert_eq!(applied.start, start);
    }

    #[test]
    fn apply_from_now_replaces_the_clock() {
        let applied = apply_plan("day_1", None, None, false, now()).unwrap();
        assert_eq!(applied.end, now() + Duration::days(1));
    }
}
