use actix_files as fs;
use actix_web::{
    get, patch, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder, Result,
};
use kv::*;
use std::{iter::Filter, time};

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct Poll {
    options: Vec<PollOption>,
    created_at: u128,
    creator: String,
    note: String,
    id: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct PollOption {
    name: String,
    votes: usize,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct PollCreateRequest {
    options: Vec<String>,
    user: ClientSideUser,
    note: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct PollVoteRequest {
    poll_id: String,
    user: ClientSideUser,
    option: u16,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct User {
    username: String,
    password_hash: String,
    votes: u32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct ClientSideUser {
    name: String,
    password_hash: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct GetPollRequest {
    id: String,
}

struct AppState {
    bucket: Bucket<'static, String, Bincode<Poll>>, // <id, poll>
    user_bucket: Bucket<'static, String, Bincode<User>>, // <name, User>
}

#[post("/create_poll")]
async fn create_poll(req_body: String, data: web::Data<AppState>) -> impl Responder {
    let create_req: PollCreateRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    println!("Recieve create_poll request {:?}", create_req);

    let user = data
        .user_bucket
        .contains(create_req.user.name.clone())
        .unwrap();
    if user {
        let id = loop {
            let buf = &mut uuid::Uuid::encode_buffer();
            let uuid = uuid::Uuid::new_v4().to_simple().encode_lower(buf);
            if !data.bucket.contains(uuid.to_owned()).unwrap() {
                break uuid.to_owned();
            }
        };

        println!("Generate uuid {}", id);

        data.bucket
            .set(
                id.clone(),
                Bincode(Poll {
                    options: create_req
                        .options
                        .iter()
                        .map(|opt| PollOption {
                            name: opt.clone(),
                            votes: 0,
                        })
                        .collect::<Vec<_>>(),
                    created_at: time::SystemTime::now()
                        .duration_since(time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis(),
                    creator: create_req.user.name,
                    note: create_req.note,
                    id: id.clone(),
                }),
            )
            .unwrap();
        data.bucket.flush_async().await.unwrap();

        HttpResponse::Ok().body(id)
    } else {
        HttpResponse::Unauthorized().body("No such user")
    }
}

#[post("/get_poll")]
async fn get_poll(req_body: String, data: web::Data<AppState>) -> impl Responder {
    let create_req: PollCreateRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    println!("Recieve create_poll request {:?}", create_req);

    let user = data.user_bucket

    let user = data
        .user_bucket
        .contains(create_req.user.name.clone())
        .unwrap();
    if user {
        let id = loop {
            let buf = &mut uuid::Uuid::encode_buffer();
            let uuid = uuid::Uuid::new_v4().to_simple().encode_lower(buf);
            if !data.bucket.contains(uuid.to_owned()).unwrap() {
                break uuid.to_owned();
            }
        };

        println!("Generate uuid {}", id);

        data.bucket
            .set(
                id.clone(),
                Bincode(Poll {
                    options: create_req
                        .options
                        .iter()
                        .map(|opt| PollOption {
                            name: opt.clone(),
                            votes: 0,
                        })
                        .collect::<Vec<_>>(),
                    created_at: time::SystemTime::now()
                        .duration_since(time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis(),
                    creator: create_req.user.name,
                    note: create_req.note,
                    id: id.clone(),
                }),
            )
            .unwrap();
        data.bucket.flush_async().await.unwrap();

        HttpResponse::Ok().body(id)
    } else {
        HttpResponse::Unauthorized().body("No such user")
    }
}

#[patch("/vote")]
async fn vote(req_body: String, data: web::Data<AppState>) -> impl Responder {
    let vote_req: PollVoteRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    println!("Recieve vote request {:?}", vote_req);

    let user = data
        .user_bucket
        .contains(vote_req.user.name.clone())
        .unwrap();
    if user {
        use std::cell::Cell;
        let successful = Cell::new(false);

        match data.bucket.transaction(|txn| {
            let poll = txn.get(vote_req.poll_id.clone())?;
            match poll {
                Some(mut poll) => {
                    poll.0.options[vote_req.option as usize].votes += 1;
                    println!("Update poll {:?}", poll.0);
                    txn.set(vote_req.poll_id.clone(), Bincode(poll.0))?;
                    successful.set(true);
                }
                None => {
                    println!("No such poll");
                    successful.set(false);
                }
            }
            Ok(())
        }) {
            Ok(_) => {
                if !successful.get() {
                    HttpResponse::NotFound().finish()
                } else {
                    data.bucket.flush_async().await.unwrap();
                    data.user_bucket.transaction(|txn| {
                        let mut user = txn.get(vote_req.user.name.clone())?.unwrap();
                        user.0.votes += 1;
                        txn.set(vote_req.user.name.clone(), Bincode(user.0))?;
                        Ok(())
                    }).unwrap();
                    HttpResponse::Ok().finish()
                }
            }
            Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        }
    } else {
        HttpResponse::Unauthorized().body("No such user")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut cfg = Config::new("./db");
    let store = Store::new(cfg).unwrap();

    HttpServer::new(move || {
        App::new()
            .service(create_poll)
            .service(vote)
            .service(
                fs::Files::new("/", "./static")
                    .show_files_listing()
                    .index_file("index.html"),
            )
            .service(create_poll)
            .data(AppState {
                bucket: store
                    .bucket::<String, Bincode<Poll>>(Some("polls"))
                    .unwrap(),
                user_bucket: store
                    .bucket::<String, Bincode<User>>(Some("users"))
                    .unwrap(),
            })
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
