use iron::prelude::*;
use iron::status;

// Every call into `iron` here goes through the glob import of the prelude, and nothing in this file
// imports the same names explicitly. The extraction of such code leaves the calls without a target
// (see `GlobCalls.ql`), so the data extension rows and the calls that match canonical paths do not
// apply and the queries have to recognize the API by its names.

fn bad_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Hello, {:?}!</h1>", res);
    // BAD: the request path is formatted into markup and returned without a content type.
    Ok(Response::with((status::Ok, response)))
}

fn bad_body_only_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    // BAD: a body modifier on its own is also served without a `Content-Type`.
    Ok(Response::with(format!("<p>{:?}</p>", res)))
}

fn bad_named_tuple_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>{:?}</h1>", res);
    // BAD: the tuple is built first and passed to `Response::with` later.
    let modifiers = (status::Ok, response);
    Ok(Response::with(modifiers))
}

fn bad_nested_tuple_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>{:?}</h1>", res);
    // BAD: modifier tuples nest, and the body is in the inner tuple.
    Ok(Response::with((status::Ok, (status::Ok, response))))
}

fn bad_query_handler(req: &mut Request) -> IronResult<Response> {
    let query = req.url.query().unwrap_or("");
    let response = format!("<p>{}</p>", query);
    // BAD: the query string is a user-controlled source as well.
    Ok(Response::with((status::Ok, response)))
}

fn bad_shadowed_handler(req: &mut Request) -> IronResult<Response> {
    let path = req.url.path();
    let path = path.join("/");
    let response = format!("<h1>{}</h1>", path);
    // BAD: the value goes through another method that has no target.
    Ok(Response::with((status::Ok, response)))
}

fn good_constant_handler(_req: &mut Request) -> IronResult<Response> {
    // GOOD: no user input in the body.
    Ok(Response::with((status::Ok, "<h1>Hello</h1>")))
}

fn good_length_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("{}", res.len());
    // GOOD: only the length of the path is written.
    Ok(Response::with((status::Ok, response)))
}

fn good_plain_text_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>{:?}</h1>", res);
    // GOOD: an explicit `text/plain` content type is set.
    let plain: iron::mime::Mime = "text/plain".parse().unwrap();
    Ok(Response::with((status::Ok, plain, response)))
}

fn good_other_request_handler(request: &str) -> IronResult<Response> {
    let response = format!("<h1>{}</h1>", request);
    // GOOD: the parameter is not an Iron request, so it is not a source.
    Ok(Response::with((status::Ok, response)))
}

fn bad_escape_default_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path().join("/").escape_default().to_string();
    let response = format!("<h1>{}</h1>", res);
    // BAD: `escape_default` keeps `<` and `>`, so it does not make the value safe for HTML.
    Ok(Response::with((status::Ok, response)))
}

fn good_html_escaped_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path().join("/").escape_html();
    let response = format!("<h1>{}</h1>", res);
    // GOOD: the method says that it escapes for HTML, and it is taken to do so.
    Ok(Response::with((status::Ok, response)))
}

use sanitizer::clean;

fn good_sanitized_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>{:?}</h1>", res);
    // GOOD: a function sanitizes the body. The call has no target, and the analysis does not follow
    // data through a call that it cannot resolve.
    let sanitized = clean(&response);
    Ok(Response::with((status::Ok, sanitized)))
}

pub fn main() {
    Iron::new(bad_handler).http("localhost:3000").unwrap();
    Iron::new(bad_body_only_handler).http("localhost:3001").unwrap();
    Iron::new(bad_named_tuple_handler).http("localhost:3002").unwrap();
    Iron::new(bad_nested_tuple_handler).http("localhost:3003").unwrap();
    Iron::new(bad_query_handler).http("localhost:3004").unwrap();
    Iron::new(bad_shadowed_handler).http("localhost:3005").unwrap();
    Iron::new(good_constant_handler).http("localhost:3006").unwrap();
    Iron::new(good_length_handler).http("localhost:3007").unwrap();
    Iron::new(good_plain_text_handler).http("localhost:3008").unwrap();
    Iron::new(bad_escape_default_handler).http("localhost:3010").unwrap();
    Iron::new(good_html_escaped_handler).http("localhost:3012").unwrap();
    Iron::new(good_sanitized_handler).http("localhost:3011").unwrap();
    Iron::new(|req: &mut Request| {
        // BAD: a closure handler, with the request in its parameter.
        let name = req.url.path();
        Ok(Response::with((status::Ok, format!("<h1>{:?}</h1>", name))))
    })
    .http("localhost:3009")
    .unwrap();
}
