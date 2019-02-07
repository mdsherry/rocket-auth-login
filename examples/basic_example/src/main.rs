#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

#[macro_use] extern crate serde;
extern crate rmp_serde as rmps;
extern crate regex;
extern crate time;
extern crate titlecase;
extern crate htmlescape;
#[allow(unused_imports)] #[macro_use] extern crate serde_json;

extern crate rocket_auth_login as auth;

use auth::authorization::*;
use rocket::response::{NamedFile, Redirect, Flash};
use rocket::response::content::Html;
use rocket::request::{FlashMessage, Form};
use rocket::http::{Cookie, Cookies};
use std::path::{Path, PathBuf};

mod administrator;
mod layout;
use administrator::*;
use layout::*;

#[allow(dead_code)]
const URL: &'static str = "http://localhost:8000";
const LOGIN_URL: &'static str = "http://localhost:8000/login";

#[get("/login", rank = 1)]
fn logged_in(_user: AuthCont<AdministratorCookie>) -> Html<String> {
    layout("You are logged in.")
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
    layout(&contents)
    
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
    let inner = form.into_inner();
    let login = inner.form;
    login.flash_redirect("/login", "/login", &mut cookies)
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
fn index(admin_opt: Option<AdministratorCookie>, flash_msg_opt: Option<FlashMessage>) -> Html<String> {
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
        
        // If using a database connection:
        // .manage(data::init_pg_pool())
        
        // using rocket_contrib's Templates
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
