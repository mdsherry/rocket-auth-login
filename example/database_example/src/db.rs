
use rocket;
use ::rocket::request::{self, FromRequest, FromForm, FormItems};
use rocket::{Request, State, Outcome};
use ::rocket::config::{Config, Environment};
use rocket::http::Status;


// use rocket::request::{self, FromRequest};

use r2d2;
use r2d2_postgres;
use r2d2_postgres::{PostgresConnectionManager, TlsMode};
// use postgres::{Connection, TlsMode};
use postgres::Connection;
use postgres;
use postgres::params::{ConnectParams, Host};
// use postgres::SslMode;
// use postgres::TlsMode;

use std::ops::Deref;
use std;
use std::env;
use dotenv::dotenv;

use super::PGCONN;

// use diesel;
// use diesel::prelude::*;
// use diesel::pg::PgConnection;


// https://github.com/sfackler/rust-postgres/issues/128
// let stmt = try!(conn.prepare("INSERT INTO foo (bar) VALUES ('baz') RETURNING id"));
// let id: i32 = try!(stmt.query(&[])).iter().next().unwrap().get(0);




// https://sfackler.github.io/r2d2-postgres/doc/v0.9.2/r2d2_postgres/struct.PostgresConnectionManager.html
// https://medium.com/@aergonaut/writing-a-github-webhook-with-rust-part-1-rocket-4426dd06d45d
// https://github.com/aergonaut/railgun/blob/master/src/railgun/db.rs

// pub type ConnectionPool = r2d2::Pool<r2d2_diesel::ConnectionManager<diesel::pg::PgConnection>>;


/// Type alias for the r2d2 connection pool. Use this as a State<T> parameter
/// in handlers that need a database connection.
type Pool = r2d2::Pool<PostgresConnectionManager>;

/// Creates the database connection pool
pub fn init_pg_pool() -> Pool {
    // let conn_str = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let config = r2d2::Config::default();
    let manager = PostgresConnectionManager::new("postgres://postgres:andrew@localhost/blog", TlsMode::None).unwrap();
    
    r2d2::Pool::new(config, manager).expect("Could not create database pool")
}

// pub fn init_pg_conn() -> Connection {
//     // let conn_str = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
//     Connection::connect("postgres://postgres:andrew@localhost/blog", postgres::TlsMode::None).unwrap()
// }


/// DbConn is a data structure that contains a database connection.
/// The DbConn also has a request guard that retrieves a connection
/// from the shared state when the route is called.
pub struct DbConn(
    pub r2d2::PooledConnection<PostgresConnectionManager>
);

/// Attempts to retrieve a single connection from the managed database pool. If
/// no pool is currently managed, fails with an `InternalServerError` status. If
/// no connections are available, fails with a `ServiceUnavailable` status.
impl<'a, 'r> FromRequest<'a, 'r> for DbConn {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<DbConn, ()> {
        let pool = request.guard::<State<Pool>>()?;
        match pool.get() {
            Ok(conn) => Outcome::Success(DbConn(conn)),
            Err(_) => Outcome::Failure((Status::ServiceUnavailable, ()))
        }
    }
}

// For the convenience of using an &DbConn as an &SqliteConnection.
impl Deref for DbConn {
    // type Target = SqliteConnection;
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


// pub fn establish_connection() -> Connection {
//     dotenv().ok();
//     let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
//     // PgConnection::establish(&database_url).expect("Error connecting to {}", database_url);
//     // Connection::connect("postgres://postgres@localhost:5433", TlsMode::None).unwrap()
//     Connection::connect(database_url, postgres::TlsMode::None).unwrap()
// }
// pub fn establish_connection_dotenv() -> Connection {
//     dotenv().ok();
//     let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
//     Connection::connect(database_url, postgres::TlsMode::None).unwrap()
// }


// pub fn get_connection() -> Connection {
//     let conn = PGCONN.lock().unwrap();
//     conn
// }



