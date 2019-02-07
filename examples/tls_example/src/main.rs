#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;

#[macro_use] extern crate serde;

extern crate rmp_serde as rmps;
extern crate regex;
extern crate time;
extern crate rand;
extern crate argon2rs;
extern crate titlecase;
extern crate htmlescape;
#[allow(unused_imports)] #[macro_use] extern crate serde_json;
#[macro_use] extern crate lazy_static;
extern crate rocket_auth_login as auth;
extern crate postgres;
extern crate r2d2;
extern crate r2d2_postgres;
extern crate dotenv;

use auth::authorization::*;
use rocket::response::{NamedFile, Redirect, Flash};
use rocket::response::content::Html;
use rocket::request::{FlashMessage, Form};
use rocket::http::{Cookie, Cookies};

use std::time::Instant;
use r2d2_postgres::{PostgresConnectionManager, TlsMode};
use postgres::Connection;

// These use statements are not needed here but
// may be convenient to have in other modules
// use r2d2;
// use r2d2_postgres;
// use postgres;

use std::sync::Mutex;
use std::path::{Path, PathBuf};

mod administrator;
mod layout;
mod db;
use administrator::*;
use layout::*;
use db::*;

#[allow(dead_code)]
const URL: &'static str = "https://localhost:8000";
const LOGIN_URL: &'static str = "https://localhost:8000/login";

// The lazy_static crate requires that global static references be wrapped in a mutex
/// The PGCONN global is used to make database connections available 
/// anywhere inside the program.  The main use in this example is to
/// allow the authenticate() method to access a database connection
/// without a database connection being passed into it.
lazy_static! {
    static ref PGCONN: Mutex<DbConn> = Mutex::new( DbConn(init_pg_pool().get().expect("Could not connect to database.")) );
}

/// The `logged_in()` method queries the database for the username specified
/// in the cookie.  In this instance all of the data in the database is also
/// contained in the cookie, making a database operation unnecessary, however
/// this is just an example to show how to connect to a database.
#[get("/login", rank = 1)]
fn logged_in(_user: AuthCont<AdministratorCookie>, conn: DbConn) -> Html<String> {
    let start = Instant::now();
    let admin: AdministratorCookie = _user.cookie;
    let qrystr = format!("SELECT userid, username, display FROM users WHERE username = '{}'", admin.username);
    let user_data_qry = conn.query(&qrystr, &[]);
    let output = match user_data_qry {
        Ok(qry) => {
            if !qry.is_empty() && qry.len() == 1 {
                let row = qry.get(0);
                
                // the display field is null so use get_opt to get a result, which unwraps to a string
                let display_opt = row.get_opt(2);
                let display = match display_opt {
                    Some(Ok(d)) => Some(d),
                    _ => None,
                };
                
                let user_results = AdministratorCookie {
                    userid: row.get(0),
                    username: row.get(1),
                    display: display,
                };
                format!("Welcome. Your info is:<br>\nId: {}<br>\nUsername: {}<br>\nDisplay name: {}", 
                    user_results.userid, user_results.username, user_results.display.unwrap_or(String::from("no display name")))
            } else {
                String::from("Could not retrieve the user from the database.")
            }
        },
        Err(err) => String::from("Could not query the database."),
    };
    let out = layout(&output);
    
    let end = start.elapsed();
    println!("Served in {}.{:08} seconds", end.as_secs(), end.subsec_nanos());
    out
}
#[get("/login", rank = 2)]
fn login() -> Html<String> {
    layout(&layout_form(LOGIN_URL))
}


/// if there is a user query string, and an optional flash message
/// display an optional flash message indicating why the login failed
/// and the login screen with user filled in
#[get("/login?<user>")]
fn retry_login_user(user: UserQuery, flash_msg_opt: Option<FlashMessage>) -> Html<String> {
    let start = Instant::now();
    
    let login_form = layout_retry_form(LOGIN_URL, &user.user);
    let alert;
    if let Some(flash) = flash_msg_opt {
        alert = alert_danger(flash.msg());
    } else { 
        alert = String::new();
    }
    let mut contents = String::with_capacity(login_form.len() + alert.len() + 20);
    contents.push_str(&alert);
    contents.push_str("\n");
    contents.push_str(&login_form);
    let output = layout(&contents);
    
    let end = start.elapsed();
    println!("Served in {}.{:08} seconds", end.as_secs(), end.subsec_nanos());
    output
}

/// if there is a flash message but no user query string
/// display why the login failed and display the login screen
#[get("/login", rank = 3)]
fn retry_login_flash(flash_msg: FlashMessage) -> Html<String> {
    println!("Retrying login...");
    let login_form = layout_form(LOGIN_URL);
    let alert = alert_danger(flash_msg.msg());
    let mut contents = String::with_capacity(login_form.len() + alert.len() + 20);
    contents.push_str(&alert);
    contents.push('\n');
    contents.push_str(&login_form);
    layout(&contents)
}

#[allow(unused_mut)]
#[post("/login", data = "<form>")]
fn process_login(form: Form<LoginCont<AdministratorForm>>, mut cookies: Cookies) -> Result<Redirect, Flash<Redirect>> {
    let start = Instant::now();
    
    let inner = form.into_inner();
    let login = inner.form;
    let output = login.flash_redirect("/login", "/login", &mut cookies);
    
    let end = start.elapsed();
    println!("Served in {}.{:08} seconds", end.as_secs(), end.subsec_nanos());
    output
}

#[get("/logout")]
fn logout(admin: Option<AdministratorCookie>, mut cookies: Cookies) -> Result<Flash<Redirect>, Redirect> {
    if let Some(_) = admin {
        cookies.remove_private(Cookie::named(AdministratorCookie::cookie_id()));
        Ok(Flash::success(Redirect::to("/"), "Successfully logged out."))
    } else {
        Err(Redirect::to("/login"))
    }
}


#[get("/")]
fn index(admin_opt: Option<AdministratorCookie>, flash_msg_opt: Option<FlashMessage>, conn: DbConn) -> Html<String> {
    let mut contents = String::with_capacity(300);
    if let Some(flash) = flash_msg_opt {
        match flash.name() {
            "success" => contents.push_str(&alert_success(flash.msg())),
            "warning" => contents.push_str(&alert_warning(flash.msg())),
            "error" => contents.push_str(&alert_danger(flash.msg())),
            _ => contents.push_str(&alert_info(flash.msg())),
        }
    }
    if let Some(admin) = admin_opt {
        contents.push_str(&format!("Welcome {}", admin.username));
    } else {
        contents.push_str(r#"<a href="/login">Login</a>"#);
    }
    layout(&contents)
}


/// static_files() is needed to serve css/js/font files
/// all static files should be placed in a folder, ex. static
/// this prevents directory traversal attacks but still
/// allows static files to be served easily
#[get("/<file..>", rank=10)]
fn static_files(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).ok()
}

fn main() {
        rocket::ignite()
        .manage(db::init_pg_pool())
        // If using rocket_contrib's Templates
        // .attach(Template::fairing())
        .mount("/", routes![
            logged_in,
            login,
            retry_login_user,
            retry_login_flash,
            process_login,
            logout,
            index,
            static_files
        ])
        .launch();
}
