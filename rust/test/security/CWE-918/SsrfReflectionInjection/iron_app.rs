use iron::prelude::*;
use iron::status;
use iron::Request;

// BAD: the full inbound request URL (whose authority comes from the attacker-controlled
// `Host` header) is fetched by the server.
pub fn bad_request_url() {
    Iron::new(|req: &mut Request| {
        let request_url = req.url.to_string(); // $ Source

        let data = reqwest::blocking::get(request_url) // $ Alert
            .expect("failed")
            .text()
            .expect("error");

        Ok(Response::with((status::Ok, data)))
    })
    .http("localhost:8080")
    .unwrap();
}

// GOOD: the request URL is only used in the path of a request to a fixed host.
pub fn good_fixed_host() {
    Iron::new(|req: &mut Request| {
        let request_url = req.url.to_owned();

        let path = format!("http://my.app/{request_url}");

        let data = reqwest::blocking::get(path)
            .expect("failed")
            .text()
            .expect("error");

        Ok(Response::with((status::Ok, data)))
    })
    .http("localhost:8081")
    .unwrap();
}
