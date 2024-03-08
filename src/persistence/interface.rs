use std::env;
use std::sync::OnceLock;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

use tokio::sync::Mutex;
use rusqlite::{Connection, OpenFlags};
use serde::{Serialize, Deserialize};

const DB_FILE_NAME: &str = "db.sqlite3";

#[derive(Serialize, Deserialize)]
pub struct Subscription {
    pub user_id: u64,
    pub cpe: String
}

#[derive(Serialize, Deserialize)]
pub struct History {
    pub user_id: u64,
    pub command: String
}

fn get_db_path() -> String {
    let mut exe_path = env::current_exe().unwrap();
    let _ = exe_path.pop();
    exe_path.push(&DB_FILE_NAME);
    exe_path.to_str().unwrap().to_string()
}

fn get_db_connection() -> &'static Mutex<Connection> {
    static CONN: OnceLock<Mutex<Connection>> = OnceLock::new();
    CONN.get_or_init(|| 
        Mutex::new(Connection::open_with_flags(get_db_path(),
            OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
        ).expect("Failed to open database file"))
    )
}

async fn store_subscription(cpe: &str, user_id: u64) -> rusqlite::Result<()> {
    let conn = get_db_connection().lock().await;

    let query = "INSERT INTO subscriptions(userid, cpe) VALUES (?1, ?2)";
    let mut stmt = conn.prepare_cached(query)?;
    stmt.execute((user_id, cpe))?;

    Ok(())
}

async fn get_subscriptions(user_id: u64) -> rusqlite::Result<Vec<Subscription>, rusqlite::Error> {
    let conn = get_db_connection().lock().await;

    let query = "SELECT * FROM subscriptions WHERE userid = ?1";
    let mut stmt = conn.prepare_cached(query)?;
    let result_iter = stmt.query_map((user_id,), |row| {
        Ok(Subscription {
            user_id: row.get(1)?,
            cpe: row.get(2)?
        })
    })?;

    let mut result: Vec<Subscription> = Vec::new();
    for sub in result_iter {
        result.push(sub?);
    }

    Ok(result)
}

async fn add_history_backend(user_id: u64, command: &str) -> rusqlite::Result<(), rusqlite::Error> {
    let conn = get_db_connection().lock().await;

    let query = "INSERT INTO history(userid, command) VALUES (?1, ?2)";
    let mut stmt = conn.prepare_cached(query)?;
    stmt.execute((user_id, command))?;

    Ok(())
}

async fn get_history_backend(user_id: u64) -> rusqlite::Result<Vec<History>, rusqlite::Error> {
    let conn = get_db_connection().lock().await;

    let query = "SELECT * FROM history WHERE userid = ?1 ORDER BY id DESC LIMIT 10";
    let mut stmt = conn.prepare_cached(query)?;
    let result_iter = stmt.query_map((user_id,), |row| {
        Ok(History {
            user_id: row.get(1)?,
            command: row.get(2)?
        })
    })?;

    let mut result: Vec<History> = Vec::new();
    for item in result_iter {
        result.push(item?);
    }

    Ok(result)
}

pub async fn initialize_db() {
    let conn = get_db_connection().lock().await;

    if let Err(e) = conn.execute(
        "CREATE TABLE IF NOT EXISTS subscriptions (
            id      INTEGER PRIMARY KEY,
            userid    INTEGER NOT NULL,
            cpe  TEXT
        )",
        (),
    ) {
        panic!("Failed to create subscriptions table: {:?}", e);
    }

    if let Err(e) = conn.execute(
        "CREATE TABLE IF NOT EXISTS history (
            id      INTEGER PRIMARY KEY,
            userid    INTEGER NOT NULL,
            command  TEXT
        )",
        (),
    ) {
        panic!("Failed to create history table: {:?}", e);
    }
}

pub async fn add_subscription(cpe: &str, user_id: u64) -> Result<(), Box<dyn Error + Send>> {
    if let Err(e) = store_subscription(cpe, user_id).await {
        return Err(Box::new(IoError::new(ErrorKind::Other, format!("{}", e))));
    }

    Ok(())
}

pub async fn retrieve_subscriptions(user_id: u64) -> Result<String, Box<dyn Error + Send>> {
    let result = get_subscriptions(user_id).await;
    if let Err(e) = result {
        return Err(Box::new(IoError::new(ErrorKind::Other, format!("{}", e))));
    }

    Ok(serde_json::to_string(&result.unwrap()).unwrap())
}

pub async fn add_history(user_id: u64, command: &str) {
    if let Err(e) = add_history_backend(user_id, command).await {
        eprintln!("Failed to insert history to DB. Error: {:?}\nCommand: {}", e, command);
    }
}

pub async fn get_history(user_id: u64) -> Result<String, Box<dyn Error + Send>> {
    let result = get_history_backend(user_id).await;
    if let Err(e) = result {
        return Err(Box::new(IoError::new(ErrorKind::Other, format!("{}", e))));
    }

    Ok(serde_json::to_string(&result.unwrap()).unwrap())
}

#[cfg(test)]
mod integration_tests {
    #[test]
    fn get_db_connection_test() {
        super::get_db_connection();
    }

    #[tokio::test]
    async fn init_db_test() {
        super::initialize_db().await;
    }
}