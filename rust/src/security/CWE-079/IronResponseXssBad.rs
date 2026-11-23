use iron::status;
use iron::{IronResult, Request, Response};

fn handler(req: &mut Request) -> IronResult<Response> {
    let name = req.url.path();
    let body = format!("<h1>Hello, {:?}!</h1>", name);
    Ok(Response::with((status::Ok, body))) // BAD: no content type, the body may be sniffed as HTML
}
