#![forbid(unsafe_code)]

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
use std::sync::Mutex;

const JWT_SECRET: &[u8] = b"SOMESECRET"; // might want to change this lmao

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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct JWTClaims {
    sub: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct TrendingPoll {
    created_at: u128,
    id: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
struct TrendingPolls {
    last_sorted: u128,
    polls: Vec<TrendingPoll>,
}

#[derive(serde::Deserialize)]
struct GetTrendingQueryParams {
    start: u64,
    end: u64,
}

#[post("/api/create_poll")]
async fn create_poll(req_body: String, storage: web::Data<AppData>, req: HttpRequest) -> impl Responder {
    let create_req: PollCreateRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };
    let storage = &storage.db;

    info!("Recieve create_poll request {:?}", create_req);

    if create_req.title.len() > 100 {
        return HttpResponse::BadRequest().body("Title is too long.");
    } else if create_req.title.is_empty() {
        return HttpResponse::BadRequest().body("Title is empty.");
    }

    if create_req.options.len() > 10 {
        return HttpResponse::BadRequest().body("Too many options.");
    } else if create_req.options.len() == 0 {
        return HttpResponse::BadRequest().body("No options.");
    }

    let users = storage.open_tree("users").unwrap();
    let polls = storage.open_tree("polls").unwrap();

    let token = req.headers().get("authorization");
    let token = match token {
        Some(token) => match token.to_str() {
            Ok(token_str) => token_str,
            Err(_) => return HttpResponse::Unauthorized().body("You aren't <a href=\"login.html\" target=\"_blank\">logged in.</a>"),
        },
        None => return HttpResponse::Unauthorized().body("You aren't <a href=\"login.html\" target=\"_blank\">logged in.</a>"),
    };
    let user = decode::<JWTClaims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &{ let mut v = Validation::new(Algorithm::HS256); v.validate_exp = false; v },
    );
    let username = match user {
        Ok(user) => user.claims.sub,
        Err(e) => return HttpResponse::Unauthorized().body("You aren't <a href=\"login.html\" target=\"_blank\">logged in.</a>"),
    };

    let user: Option<User> = users.get(&username).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap());
    match user {
        Some(mut user) => {
            let id = loop {
                let buf = &mut uuid::Uuid::encode_buffer();
                let uuid = uuid::Uuid::new_v4().to_simple().encode_lower(buf);
                if !polls.contains_key(uuid.to_owned()).unwrap() {
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
            polls.insert(&id, bincode::serialize(&new_poll).unwrap()).unwrap();

            user.polls.push(id.clone());
            users.insert(&username, bincode::serialize(&user).unwrap()).unwrap();

            let now = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_millis();

            let mut trending: TrendingPolls = storage.get("trending").unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap()).unwrap();
            if now - trending.last_sorted > 3.6e+6 as u128 {
                trending.polls.retain(|poll| {
                    let diff = now - poll.created_at;
                    diff <= 2.592e+8 as u128 // 3 days
                });
                trending.polls.sort_unstable_by(|a, b| {
                    use futures::executor::block_on;
                    block_on(async {
                        let a: Poll = polls.get(a.id.clone()).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap()).unwrap();
                        let b: Poll = polls.get(b.id.clone()).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap()).unwrap();
    
                        let time_a = now - a.created_at;
                        let time_b = now - b.created_at;
        
                        let a_votes = a.options.iter().map(|opt| opt.votes).sum::<usize>();
                        let b_votes = b.options.iter().map(|opt| opt.votes).sum::<usize>();
    
                        let a = a_votes / time_a as usize;
                        let b = b_votes / time_b as usize;
        
                        b.partial_cmp(&a).unwrap()
                    })
                });
                trending.last_sorted = now;
            }
            
            trending.polls.push(TrendingPoll {
                created_at: new_poll.created_at,
                id: id.clone(),
            });

            storage.insert("trending", bincode::serialize(&trending).unwrap()).unwrap();

            return HttpResponse::Ok().body(id);
        }
        None => return HttpResponse::Unauthorized().body("No such user"),
    }
}

#[post("/api/sign_up")]
async fn sign_up(req_body: String, storage: web::Data<AppData>) -> impl Responder {
    let create_req: SignupRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };
    let storage = &storage.db;

    info!("Recieve sign_up request {:?}", create_req);

    let users = storage.open_tree("users").unwrap();

    if create_req.name.len() > 30 {
        return HttpResponse::BadRequest().body("Name is too long.");
    } else if create_req.name.is_empty() {
        return HttpResponse::BadRequest().body("Name is empty.");
    }

    if create_req.password.len() > 30 {
        return HttpResponse::BadRequest().body("Password is too long.");
    } else if create_req.password.is_empty() {
        return HttpResponse::BadRequest().body("Password is empty.");
    }

    if users.contains_key(&create_req.name).unwrap() {
        return HttpResponse::BadRequest().body("That username is taken.");
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
        users.insert(&create_req.name, bincode::serialize(&new_user).unwrap()).unwrap();
        let token = encode(
            &Header::default(),
            &JWTClaims { sub: create_req.name },
            &EncodingKey::from_secret(JWT_SECRET.as_ref()),
        )
        .unwrap();
        HttpResponse::Ok().body(token)
    }
}

#[post("/api/login")]
async fn login(req_body: String, storage: web::Data<AppData>) -> impl Responder {
    let check_req: ClientSideUser = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };
    let storage = &storage.db;

    info!("Recieve login request {:?}", check_req);

    let users = storage.open_tree("users").unwrap();

    let user: Option<User> = users.get(&check_req.name).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap());
    match user {
        Some(user) => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(check_req.password.as_bytes());
            let result = hasher.finalize();
            if user.password_hash[..] == result[..] {
                let token = encode(
                    &Header::default(),
                    &JWTClaims { sub: check_req.name },
                    &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                )
                .unwrap();
                return HttpResponse::Ok().body(token);
            } else {
                return HttpResponse::Unauthorized().body("You are not logged in.");
            }
        }
        None => return HttpResponse::Unauthorized().body("You are not logged in."),
    }
}

#[get("/api/self")]
async fn get_self(storage: web::Data<AppData>, req: HttpRequest) -> impl Responder {
    let storage = &storage.db;
    let users = storage.open_tree("users").unwrap();

    let token = req.headers().get("authorization");
    let token = match token {
        Some(token) => match token.to_str() {
            Ok(token_str) => token_str,
            Err(_) => return HttpResponse::Unauthorized().body("You are not logged in."),
        },
        None => return HttpResponse::Unauthorized().body("You are not logged in."),
    };
    let user = decode::<JWTClaims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &{ let mut v = Validation::new(Algorithm::HS256); v.validate_exp = false; v },
    );
    let username = match user {
        Ok(user) => user.claims.sub,
        Err(e) => return HttpResponse::Unauthorized().body(format!("Failed to log in.")),
    };

    let user: Option<User> = users.get(&username).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap());

    match user {
        Some(user) => {
            return HttpResponse::Ok().body(serde_json::to_string(&GetUserResponse {
                name: user.name.clone(),
                polls: user.polls.len() as u32,
                votes: user.votes.len() as u32,
            }).unwrap())
        }
        None => return HttpResponse::Unauthorized().body("No such user"),
    }
}

#[get("/api/profile/{name}")]
async fn profile(storage: web::Data<AppData>, path: web::Path<(String,)>) -> impl Responder {
    let storage = &storage.db;
    let name = path.into_inner().0;
    info!("Recieve profile request {}", name);

    let users = storage.open_tree("users").unwrap();

    let user: Option<User> = users.get(&name).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap());
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
async fn get_poll(storage: web::Data<AppData>, path: web::Path<(String,)>, req: HttpRequest) -> impl Responder {
    let id = path.into_inner().0;
    let storage = &storage.db;

    info!("Recieve poll request {}", id);

    let polls = storage.open_tree("polls").unwrap();
    let users = storage.open_tree("users").unwrap();

    let token = req.headers().get("authorization");
    let token = match token {
        Some(token) => match token.to_str() {
            Ok(token_str) => token_str,
            Err(_) => return HttpResponse::Unauthorized().body("You are not logged in."),
        },
        None => {
            let poll: Option<Poll> = polls.get(&id).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap());
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
    let user = decode::<JWTClaims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &{ let mut v = Validation::new(Algorithm::HS256); v.validate_exp = false; v },
    );
    let username = match user {
        Ok(user) => user.claims.sub,
        Err(_) => return HttpResponse::Unauthorized().body("You are not logged in."),
    };

    let user: Option<User> = users.get(&username).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap());

    match user {
        Some(user) => {
            let poll: Option<Poll> = polls.get(&id).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap());
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
        None => return HttpResponse::Unauthorized().body("You are not logged in."),
    }
}

#[get("/api/trending")]
async fn get_trending(storage: web::Data<AppData>, req: HttpRequest, mut info: web::Query<GetTrendingQueryParams>) -> impl Responder {
    let storage = &storage.db;

    let polls = storage.open_tree("polls").unwrap();
    let users = storage.open_tree("users").unwrap();
    
    let trending: TrendingPolls = bincode::deserialize(&storage.get("trending").unwrap().unwrap()).unwrap();

    let mut compiled_trending: Vec<GetPollResponse> = Vec::new();

    let token = req.headers().get("authorization");
    let token = match token {
        Some(token) => match token.to_str() {
            Ok(token_str) => token_str,
            Err(_) => return HttpResponse::Unauthorized().body("You are not logged in."),
        },
        None => {
            if info.start > trending.polls.len() as u64 {
                return HttpResponse::BadRequest().body("Invalid index");
            }
            if info.end > trending.polls.len() as u64 {
                info.end = trending.polls.len() as u64;
            }

            for i in info.start..info.end {
                let poll = &trending.polls[i as usize];
                let db_poll: Poll = bincode::deserialize(&polls.get(&poll.id).unwrap().unwrap()).unwrap();
                let poll_resp = GetPollResponse {
                    title: db_poll.title,
                    options: db_poll.options,
                    created_at: db_poll.created_at,
                    id: db_poll.id,
                    creator: db_poll.creator,
                    voted_for: None
                };
                compiled_trending.push(poll_resp);
            }

            return HttpResponse::Ok().body(serde_json::to_string(&compiled_trending).unwrap());
        },
    };
    let user = decode::<JWTClaims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &{ let mut v = Validation::new(Algorithm::HS256); v.validate_exp = false; v },
    );
    let username = match user {
        Ok(user) => user.claims.sub,
        Err(_) => return HttpResponse::Unauthorized().body("You are not logged in."),
    };

    let user: Option<User> = users.get(&username).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap());

    match user {
        Some(user) => {
            if info.start > trending.polls.len() as u64 {
                return HttpResponse::BadRequest().body("Invalid index");
            }
            if info.end > trending.polls.len() as u64 {
                info.end = trending.polls.len() as u64;
            }

            for i in info.start..info.end {
                let poll = &trending.polls[i as usize];
                let db_poll: Poll = bincode::deserialize(&polls.get(&poll.id).unwrap().unwrap()).unwrap();
                let poll_resp = GetPollResponse {
                    title: db_poll.title,
                    options: db_poll.options,
                    created_at: db_poll.created_at,
                    id: db_poll.id.clone(),
                    creator: db_poll.creator,
                    voted_for: user.votes.get(&db_poll.id).map(|v| *v)
                };
                compiled_trending.push(poll_resp);
            }

            return HttpResponse::Ok().body(serde_json::to_string(&compiled_trending).unwrap());
        },
        None => return HttpResponse::Unauthorized().body("You are not logged in."),
    }
}

#[patch("/api/vote")]
async fn vote(req_body: String, storage: web::Data<AppData>, req: HttpRequest) -> impl Responder {
    let vote_req: PollVoteRequest = match serde_json::from_str(req_body.as_str()) {
        Ok(req) => req,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };
    let storage = &storage.db;

    //info!("Recieve vote request {:?}", vote_req);

    let users = storage.open_tree("users").unwrap();
    let polls = storage.open_tree("polls").unwrap();

    let token = req.headers().get("authorization");
    let token = match token {
        Some(token) => match token.to_str() {
            Ok(token_str) => token_str,
            Err(_) => return HttpResponse::Unauthorized().body("You are not logged in."),
        },
        None => return HttpResponse::Unauthorized().body("You are not logged in."),
    };
    let user = decode::<JWTClaims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &{ let mut v = Validation::new(Algorithm::HS256); v.validate_exp = false; v },
    );
    let username = match user {
        Ok(user) => user.claims.sub,
        Err(_) => return HttpResponse::Unauthorized().body("You are not logged in."),
    };

    let user: Option<User> = users.get(&username).unwrap().map(|u| bincode::deserialize(u.as_ref()).unwrap());
    match user {
        Some(mut user) => {
            if user.votes.contains_key(&vote_req.poll_id) {
                return HttpResponse::BadRequest().body("You already voted.");
            }
            
            let res: sled::transaction::TransactionResult<(), HttpResponse> = polls.transaction(|txn| {
                let poll: Option<Poll> = txn.get(&vote_req.poll_id)?.map(|p| bincode::deserialize(p.as_ref()).unwrap());
                if poll.is_none() {
                    sled::transaction::abort(HttpResponse::NotFound().body("Poll not found"))?;
                }
                let mut poll = poll.unwrap();
                match poll.options.get_mut(vote_req.option as usize) {
                    Some(mut opt) => {
                        info!("Add vote");
                        opt.votes += 1;
                    }
                    None => sled::transaction::abort(HttpResponse::BadRequest().body("No such option."))?
                }
                txn.insert(poll.id.as_bytes(), bincode::serialize(&poll).unwrap()).unwrap();
                Ok(())
            });
            match res {
                Ok(_) => {},
                Err(e) => return HttpResponse::BadRequest().finish(),
            }

            user.votes.insert(vote_req.poll_id, vote_req.option);
            users.insert(&user.name, bincode::serialize(&user).unwrap()).unwrap();

            HttpResponse::Ok().finish()
        }
        None => return HttpResponse::Unauthorized().body("You are not logged in."),
    }
}

struct AppData {
    db: sled::Db
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let db: sled::Db = sled::open("db").unwrap();
    
    if !db.contains_key("trending").unwrap() {
        let temp: TrendingPolls = TrendingPolls { last_sorted: time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_millis(), polls: Vec::new() };
        db.insert("trending", bincode::serialize(&temp).unwrap()).unwrap();
    }

    HttpServer::new(move || {
        App::new()
            .service(create_poll)
            .service(sign_up)
            .service(vote)
            .service(profile)
            .service(login)
            .service(get_poll)
            .service(get_self)
            .service(get_trending)
            .service(
                fs::Files::new("/", "./static")
                    .show_files_listing()
                    .index_file("index.html"),
            )
            .data(AppData { db: db.clone() })
    })
    .bind("0.0.0.0:80")?
    .run()
    .await
}
