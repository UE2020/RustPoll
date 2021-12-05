# RustPoll

A poll app written in Rust using the Actix webserver. The client is a little shoddy and could use a code-refactor, but other than that, I consider this application to be completed.

## Config

Configuration is extremely simple. Just set the `JWT_SECRET` secret constant in src/main.rs, and run it using `cargo run --release`. Making sure that the `JWT_SECRET` is not leaked is extremely important, as the security of your application could be compromised if it is leaked.

## Security

Passwords are hashed using SHA256. Although it'd be quite easy to implement, tokens do not expire at the moment.

## Trending Algorithm

Polls are sorted using by generating a ranking for every poll. The ranking is a number that is determined by dividing the total amount of votes that a poll has by its age (UNIX time milliseconds).
