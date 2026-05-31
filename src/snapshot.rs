use std::time::{SystemTime, UNIX_EPOCH};

const PARTIAL_PREFIX: &str = ".partial-";

// Dependency-less conversion from "days since 1970" into (year, month, day), using
// Hinnant's civil_from_days: https://howardhinnant.github.io/date_algorithms.html
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    (y, m, d)
}

fn utc_timestamp() -> String {
    let seconds_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let days_since_epoch = (seconds_since_epoch / 86400) as i64;
    let (year, month, day) = civil_from_days(days_since_epoch);

    let time_of_day = seconds_since_epoch % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}_{hour:02}-{minute:02}-{seconds:02}Z")
}

pub fn new_export() -> String {
    let timestamp = utc_timestamp();
    format!("export-{timestamp}")
}

pub fn to_partial(name: &str) -> String {
    format!("{PARTIAL_PREFIX}{name}")
}

pub fn is_partial(name: &str) -> bool {
    name.starts_with(PARTIAL_PREFIX)
}
