use iron::mime::Mime;
use iron::status;
use iron::{Chain, Iron, IronResult, Request, Response};

fn bad_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    // BAD: the request path is formatted into markup and returned without encoding.
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    Ok(Response::with((status::Ok, response)))
}

fn bad_body_only_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    // BAD: a body modifier on its own is also served without a `Content-Type`. It is not a tuple,
    // so it is covered by the `Response::with` sink model and not by the tuple query.
    Ok(Response::with(format!("<p>{:?}</p>", res)))
}

fn good_plain_text_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // GOOD: an explicit `text/plain` content type is set.
    let plain: Mime = "text/plain".parse().unwrap();
    Ok(Response::with((status::Ok, plain, response)))
}

fn good_json_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("{{\"path\": {:?}}}", res);
    // GOOD: an explicit `application/json` content type is set.
    let json: Mime = "application/json".parse().unwrap();
    Ok(Response::with((status::Ok, json, response)))
}

fn good_constant_handler(_req: &mut Request) -> IronResult<Response> {
    // GOOD: no user input in the body.
    Ok(Response::with((status::Ok, "<h1>Hello</h1>")))
}

mod prelude_style {
    use iron::prelude::*;
    use iron::status;

    pub fn handler(req: &mut Request) -> IronResult<Response> {
        let res = req.url.path();
        let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
        // BAD: same as `bad_handler`, using the `iron::prelude` imports.
        Ok(Response::with((status::Ok, response)))
    }
}

fn bad_named_tuple_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // BAD: the tuple is built first and passed to `Response::with` later.
    let modifiers = (status::Ok, response);
    Ok(Response::with(modifiers))
}

fn bad_html_mime_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // BAD: an explicit `text/html` content type does not make the body safe.
    let html: Mime = "text/html".parse().unwrap();
    Ok(Response::with((status::Ok, html, response)))
}

fn main() {
    Iron::new(bad_handler).http("localhost:3000").unwrap();
    Iron::new(Chain::new(bad_body_only_handler)).http("localhost:3001").unwrap();
    Iron::new(good_plain_text_handler).http("localhost:3002").unwrap();
    Iron::new(good_json_handler).http("localhost:3003").unwrap();
    Iron::new(good_constant_handler).http("localhost:3004").unwrap();
    Iron::new(prelude_style::handler).http("localhost:3005").unwrap();
    Iron::new(bad_named_tuple_handler).http("localhost:3006").unwrap();
    Iron::new(bad_html_mime_handler).http("localhost:3007").unwrap();
}
