use std::env;
use std::sync::OnceLock;
use tokio::sync::Mutex;
use rusqlite::{Connection, OpenFlags};

const DB_FILE_NAME: &str = "db.sqlite3";

fn get_db_path() -> String {
    let mut exe_path = env::current_exe().unwrap();
    let _ = exe_path.pop();
    let exe_path = exe_path.join(&DB_FILE_NAME);
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

pub async fn initialize_db() {
    let conn = get_db_connection().lock().await;

    let _ = conn.execute(
        "CREATE TABLE subscriptions (
            id    INTEGER PRIMARY KEY,
            uid  TEXT NOT NULL,
            cpe  BLOB
        )",
        (),
    );
}