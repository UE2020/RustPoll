use actix_files as fs;
use actix_storage::Storage;
use actix_storage_sled::SledStore;
use actix_web::{
    get, guard::Get, patch, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::*;
use sha2::Digest;
use std::{collections::HashMap, time};

const JWT_SECRET: &[u8] = b"gtszzkbqWkAKQNWXafYYRmYP7L34CqMaLGsf8Vh6BbBjdvm67E57PKUs7qBaxmS4";

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
    title: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct PollVoteRequest {
    poll_id: String,
    option: u16,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct User {
    name: String,
    password_hash: Vec<u8>,
    votes: HashMap<String, u16>,
    polls: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct ClientSideUser {
    name: String,
    password: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct GetUserResponse {
    name: String,
    votes: u32,
    polls: u32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct GetPollResponse {
    options: Vec<PollOption>,
    created_at: u128,
    creator: String,
    title: String,
    id: String,
    voted_for: Option<u16>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct SignupRequest {
    name: String,
    password: String,
}

#[post("/api/create_poll")]
async fn create_poll(req_body: String, storage: Storage, req: HttpRequest) -> impl Responder {
    let create_req: PollCreateRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    info!("Recieve create_poll request {:?}", create_req);

    let users = storage.scope("users");
    let polls = storage.scope("polls");

    let token = req.headers().get("authorization");
    let token = match token {
        Some(token) => match token.to_str() {
            Ok(token_str) => token_str,
            Err(_) => return HttpResponse::Unauthorized().body("Bad auth"),
        },
        None => return HttpResponse::Unauthorized().body("No auth"),
    };
    let user = decode::<String>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::new(Algorithm::HS256),
    );
    let username = match user {
        Ok(user) => user.claims,
        Err(_) => return HttpResponse::Unauthorized().body("Bad auth"),
    };

    let user: Option<User> = users.get(username.clone()).await.unwrap();
    match user {
        Some(user) => {
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
                creator: username.clone(),
                title: create_req.title,
                id: id.clone(),
            };
            polls.set(id.clone(), &new_poll).await.unwrap();
            return HttpResponse::Ok().body(id);
        }
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
        return HttpResponse::BadRequest().body("User already exists");
    } else {
        let mut hasher = sha2::Sha256::new();
        hasher.update(create_req.password.as_bytes());
        let result = hasher.finalize();
        let new_user = User {
            name: create_req.name.clone(),
            password_hash: result[..].to_vec(),
            votes: HashMap::new(),
            polls: Vec::new(),
        };
        users.set(create_req.name.clone(), &new_user).await.unwrap();
        let token = encode(
            &Header::default(),
            &create_req.name,
            &EncodingKey::from_secret(JWT_SECRET.as_ref()),
        )
        .unwrap();
        println!("Token {}", token);
        HttpResponse::Ok().body(token)
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

    let user: Option<User> = users.get(check_req.name.clone()).await.unwrap();
    match user {
        Some(user) => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(check_req.password.as_bytes());
            let result = hasher.finalize();
            if user.password_hash[..] == result[..] {
                let token = encode(
                    &Header::default(),
                    &check_req.name,
                    &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                )
                .unwrap();
                println!("Token {}", token);
                return HttpResponse::Ok().body(token);
            } else {
                return HttpResponse::Unauthorized().body("Bad auth");
            }
        }
        None => return HttpResponse::Unauthorized().body("Bad auth"),
    }
}

#[get("/api/self")]
async fn get_self(storage: Storage, req: HttpRequest) -> impl Responder {
    let users = storage.scope("users");

    let token = req.headers().get("authorization");
    let token = match token {
        Some(token) => match token.to_str() {
            Ok(token_str) => token_str,
            Err(_) => return HttpResponse::Unauthorized().body("Bad auth"),
        },
        None => return HttpResponse::Unauthorized().body("No auth"),
    };
    let user = decode::<String>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::new(Algorithm::HS256),
    );
    let username = match user {
        Ok(user) => user.claims,
        Err(_) => return HttpResponse::Unauthorized().body("Bad auth"),
    };

    let user: Option<User> = users.get(username.clone()).await.unwrap();

    match user {
        Some(user) => {
            return HttpResponse::Ok().body(serde_json::to_string(&GetUserResponse {
                name: user.name.clone(),
                polls: user.polls.len() as u32,
                votes: user.votes.len() as u32,
            }).unwrap())
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
            return HttpResponse::Ok().body(serde_json::to_string(&resp).unwrap());
        }
        None => return HttpResponse::NotFound().body("No such user"),
    }
}

#[get("/api/poll/{id}")]
async fn get_poll(storage: Storage, path: web::Path<(String,)>, req: HttpRequest) -> impl Responder {
    let id = path.into_inner().0;
    info!("Recieve poll request {}", id);

    let polls = storage.scope("polls");
    let users = storage.scope("users");

    let token = req.headers().get("authorization");
    let token = match token {
        Some(token) => match token.to_str() {
            Ok(token_str) => token_str,
            Err(_) => return HttpResponse::Unauthorized().body("Bad auth"),
        },
        None => {
            let poll: Option<Poll> = polls.get(id.clone()).await.unwrap();
            match poll {
                Some(poll) => {
                    return HttpResponse::Ok().body(serde_json::to_string(&GetPollResponse {
                        title: poll.title,
                        options: poll.options,
                        created_at: poll.created_at,
                        id: poll.id,
                        creator: poll.creator,
                        voted_for: None
                    }).unwrap())
                },
                None => return HttpResponse::NotFound().body("No such poll"),
            }
        },
    };
    let user = decode::<String>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::new(Algorithm::HS256),
    );
    let username = match user {
        Ok(user) => user.claims,
        Err(_) => return HttpResponse::Unauthorized().body("Bad auth"),
    };

    let user: Option<User> = users.get(username.clone()).await.unwrap();

    match user {
        Some(user) => {
            let poll: Option<Poll> = polls.get(id.clone()).await.unwrap();
            match poll {
                Some(poll) => {
                    return HttpResponse::Ok().body(serde_json::to_string(&GetPollResponse {
                        title: poll.title,
                        options: poll.options,
                        created_at: poll.created_at,
                        id: poll.id,
                        creator: poll.creator,
                        voted_for: user.votes.get(&id).map(|v| *v)
                    }).unwrap())
                },
                None => return HttpResponse::NotFound().body("No such poll"),
            }
        },
        None => return HttpResponse::Unauthorized().body("Bad auth"),
    }
}

#[patch("/api/vote")]
async fn vote(req_body: String, storage: Storage, req: HttpRequest) -> impl Responder {
    let vote_req: PollVoteRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    info!("Recieve vote request {:?}", vote_req);

    let users = storage.scope("users");
    let polls = storage.scope("polls");

    let token = req.headers().get("authorization");
    let token = match token {
        Some(token) => match token.to_str() {
            Ok(token_str) => token_str,
            Err(_) => return HttpResponse::Unauthorized().body("Bad auth"),
        },
        None => return HttpResponse::Unauthorized().body("No auth"),
    };
    let user = decode::<String>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::new(Algorithm::HS256),
    );
    let username = match user {
        Ok(user) => user.claims,
        Err(_) => return HttpResponse::Unauthorized().body("Bad auth"),
    };

    let user: Option<User> = users.get(username.clone()).await.unwrap();
    match user {
        Some(mut user) => {
            let poll: Option<Poll> = polls.get(vote_req.poll_id.clone()).await.unwrap();
            match poll {
                Some(mut poll) => {
                    match poll.options.get_mut(vote_req.option as usize) {
                        Some(mut opt) => {
                            opt.votes += 1;
                            user.votes.insert(poll.id.clone(), vote_req.option);
                        }
                        None => return HttpResponse::BadRequest().body("No such option"),
                    }
                    polls.set(poll.id.clone(), &poll).await.unwrap();
                    users.set(user.name.clone(), &user).await.unwrap();
                    HttpResponse::Ok().finish()
                }
                None => return HttpResponse::NotFound().body("No such poll"),
            }
        }
        None => return HttpResponse::Unauthorized().body("Bad auth"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let db = SledStore::new().expect("Error opening the database");
    let storage = Storage::build()
        .store(db)
        .format(actix_storage::Format::Bincode)
        .finish();

    HttpServer::new(move || {
        App::new()
            .service(create_poll)
            .service(sign_up)
            .service(vote)
            .service(profile)
            .service(login)
            .service(get_poll)
            .service(get_self)
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
