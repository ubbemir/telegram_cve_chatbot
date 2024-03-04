use std::env;
use std::sync::OnceLock;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

use tokio::sync::Mutex;
use rusqlite::{Connection, OpenFlags};

const DB_FILE_NAME: &str = "db.sqlite3";

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
}

pub async fn add_subscription(cpe: &str, user_id: u64) -> Result<(), Box<dyn Error + Send>> {
    if let Err(e) = store_subscription(cpe, user_id).await {
        return Err(Box::new(IoError::new(ErrorKind::Other, format!("{}", e))));
    }

    Ok(())
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