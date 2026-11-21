use iron::mime::Mime;
use iron::status;
use iron::{IronResult, Request, Response};

fn handler(req: &mut Request) -> IronResult<Response> {
    let name = req.url.path();
    let body = format!("Hello, {:?}!", name);
    let plain: Mime = "text/plain".parse().unwrap();
    Ok(Response::with((status::Ok, plain, body))) // GOOD: the body is declared as plain text
}
