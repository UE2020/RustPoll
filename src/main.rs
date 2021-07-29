use actix_files as fs;
use actix_storage::Storage;
use actix_storage_sled::SledStore;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, get, patch, post, web};
use std::{time};
use log::*;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct Poll {
    options: Vec<PollOption>,
    created_at: u128,
    creator: String,
    title: String,
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
    title: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct PollVoteRequest {
    poll_id: String,
    user: ClientSideUser,
    option: u16,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct User {
    name: String,
    password_hash: String,
    votes: std::collections::HashSet<UserVoteDescriptor>,
    polls: std::collections::HashSet<UserVoteDescriptor>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug, Eq, PartialOrd, Ord, Hash)]
struct UserVoteDescriptor {
    poll: String,
    option: u16,
}


#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct ClientSideUser {
    name: String,
    password_hash: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct GetUserResponse {
    name: String,
    votes: u32,
    polls: u32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct SignupRequest {
    name: String,
    password_hash: String,
}

#[post("/api/create_poll")]
async fn create_poll(req_body: String, storage: Storage) -> impl Responder {
    let create_req: PollCreateRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    info!("Recieve create_poll request {:?}", create_req);

    let users = storage.scope("users");
    let polls = storage.scope("polls");

    let user: Option<User> = users.get(create_req.user.name.clone()).await.unwrap();
    match user {
        Some(user) => {
            if user.password_hash == create_req.user.password_hash {
                let id = loop {
                    let buf = &mut uuid::Uuid::encode_buffer();
                    let uuid = uuid::Uuid::new_v4().to_simple().encode_lower(buf);
                    if !storage.contains_key(uuid.to_owned()).await.unwrap() {
                        break uuid.to_owned();
                    }
                };

                let new_poll = Poll {
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
                    title: create_req.title,
                    id: id.clone(),
                };
                polls.set(id.clone(), &new_poll).await.unwrap();
                return HttpResponse::Ok().body(id)
            } else {
                return HttpResponse::Unauthorized().body("Bad auth")
            }
        },
        None => return HttpResponse::Unauthorized().body("No such user"),
    }
}

#[post("/api/sign_up")]
async fn sign_up(req_body: String, storage: Storage) -> impl Responder {
    let create_req: SignupRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    info!("Recieve sign_up request {:?}", create_req);

    let users = storage.scope("users");

    if users.contains_key(create_req.name.clone()).await.unwrap() {
        return HttpResponse::BadRequest().body("User already exists")
    } else {
        let new_user = User {
            name: create_req.name.clone(),
            password_hash: create_req.password_hash.clone(),
            votes: std::collections::HashSet::new(),
            polls: std::collections::HashSet::new(),
        };
        users.set(create_req.name, &new_user).await.unwrap();
        HttpResponse::Ok().finish()
    }
}

#[post("/api/login")]
async fn login(req_body: String, storage: Storage) -> impl Responder {
    let check_req: ClientSideUser = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    info!("Recieve login request {:?}", check_req);

    let users = storage.scope("users");

    let user: Option<User> = users.get(check_req.name).await.unwrap();
    match user {
        Some(user) => if user.password_hash == check_req.password_hash {
            return HttpResponse::Ok().finish()
        } else {
            return HttpResponse::Unauthorized().body("Bad auth")
        }
        None => return HttpResponse::Unauthorized().body("Bad auth"),
    }
}

#[get("/api/profile/{name}")]
async fn profile(storage: Storage, path: web::Path<(String,)>) -> impl Responder {
    let name = path.into_inner().0;
    info!("Recieve profile request {}", name);

    let users = storage.scope("users");

    let user: Option<User> = users.get(name.clone()).await.unwrap();
    match user {
        Some(user) => {
            let resp = GetUserResponse {
                name: user.name,
                votes: user.votes.len() as u32,
                polls: user.polls.len() as u32,
            };
            return HttpResponse::Ok().body(serde_json::to_string(&resp).unwrap())
        }
        None => return HttpResponse::NotFound().body("No such user"),
    }
}

#[get("/api/poll/{id}")]
async fn get_poll(storage: Storage, path: web::Path<(String,)>, req: HttpRequest) -> impl Responder {
    let id = path.into_inner().0;
    info!("Recieve poll request {}", id);

    let name = req.headers().get("auth-name");
    let password = req.headers().get("auth-password");

    let polls = storage.scope("polls");

    let poll: Option<Poll> = polls.get(id.clone()).await.unwrap();
    match poll {
        Some(poll) => {
            return HttpResponse::Ok().body(serde_json::to_string(&poll).unwrap())
        }
        None => return HttpResponse::NotFound().body("No such poll"),
    }
}

#[patch("/api/vote")]
async fn vote(req_body: String, storage: Storage) -> impl Responder {
    let vote_req: PollVoteRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    info!("Recieve vote request {:?}", vote_req);

    let users = storage.scope("users");
    let polls = storage.scope("polls");

    let user: Option<User> = users.get(vote_req.user.name.clone()).await.unwrap();
    match user {
        Some(mut user) => {
            if user.password_hash == vote_req.user.password_hash {
                let poll: Option<Poll> = polls.get(vote_req.poll_id.clone()).await.unwrap();
                match poll {
                    Some(mut poll) => {
                        match poll.options.get_mut(vote_req.option as usize) {
                            Some(mut opt) => {
                                opt.votes += 1;
                                user.votes.insert(UserVoteDescriptor {
                                    poll: poll.id.clone(),
                                    option: vote_req.option,
                                });
                            }
                            None => return HttpResponse::BadRequest().body("No such option"),
                        }
                        polls.set(poll.id.clone(), &poll).await.unwrap();
                        users.set(user.name.clone(), &user).await.unwrap();
                        HttpResponse::Ok().finish()
                    },
                    None => return HttpResponse::NotFound().body("No such poll"),
                }
            } else {
                return HttpResponse::Unauthorized().body("Bad auth")
            }
        },
        None => return HttpResponse::Unauthorized().body("No such user"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let db = SledStore::new().expect("Error opening the database");
    let storage = Storage::build().store(db).format(actix_storage::Format::Bincode).finish();

    HttpServer::new(move || {
        App::new()
        .service(create_poll)
        .service(sign_up)
        .service(vote)
        .service(profile)
        .service(login)
        .service(get_poll)
            .service(
                fs::Files::new("/", "./static")
                    .show_files_listing()
                    .index_file("index.html"),
            )
            .app_data(storage.clone())
    })
    .bind("localhost:8080")?
    .run()
    .await
}
