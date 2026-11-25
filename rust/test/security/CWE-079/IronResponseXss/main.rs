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

fn bad_parsed_literal_in_body_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    // BAD: a parsed literal that is only formatted into the body is not a content type modifier.
    let label = "text/plain".parse::<String>().unwrap();
    let response = format!("<h1>{} {:?}!</h1>", label, res);
    Ok(Response::with((status::Ok, response)))
}

fn bad_mixed_mime_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // BAD: the content type is plain text on one branch and HTML on the other, so the body can still be
    // rendered as HTML.
    let mime: Mime = if res.len() > 3 {
        "text/plain".parse().unwrap()
    } else {
        "text/html".parse().unwrap()
    };
    Ok(Response::with((status::Ok, mime, response)))
}

fn bad_nested_tuple_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // BAD: modifier tuples nest, and the body is in the inner tuple.
    Ok(Response::with((status::Ok, (status::Ok, response))))
}

fn bad_nested_named_tuple_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // BAD: the inner tuple is built first and nested later.
    let inner = (status::Ok, response);
    Ok(Response::with((status::Ok, inner)))
}

fn bad_overriding_mime_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // BAD: the `text/html` modifier is applied after the `text/plain` one, so the body is served as HTML.
    let plain: Mime = "text/plain".parse().unwrap();
    let html: Mime = "text/html".parse().unwrap();
    Ok(Response::with((status::Ok, plain, html, response)))
}

fn good_nested_plain_text_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // GOOD: the `text/plain` content type is in the inner tuple and applies to the whole response.
    let plain: Mime = "text/plain".parse().unwrap();
    Ok(Response::with((status::Ok, (plain, response))))
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
    Iron::new(bad_parsed_literal_in_body_handler).http("localhost:3008").unwrap();
    Iron::new(bad_mixed_mime_handler).http("localhost:3009").unwrap();
    Iron::new(bad_nested_tuple_handler).http("localhost:3010").unwrap();
    Iron::new(bad_overriding_mime_handler).http("localhost:3011").unwrap();
    Iron::new(good_nested_plain_text_handler).http("localhost:3012").unwrap();
    Iron::new(bad_nested_named_tuple_handler).http("localhost:3013").unwrap();
    Iron::new(missed_field_assigned_later_handler).http("localhost:3014").unwrap();
}

fn missed_field_assigned_later_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // MISSED (known limitation): the body is assigned to a tuple field after the tuple is built, so the
    // sink is the original `String::new()` expression and not the assigned value.
    let mut modifiers = (status::Ok, String::new());
    modifiers.1 = response;
    Ok(Response::with(modifiers))
}

fn bad_unregistered_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Hello, {:?}!</h1>", res);
    // BAD: no call of `Iron::new` or `Chain::new` in this file passes the handler on (a router, for
    // example, registers it), and a function that takes a request is a handler all the same.
    Ok(Response::with((status::Ok, response)))
}

fn bad_unregistered_body_only_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Hello, {:?}!</h1>", res);
    // BAD: a body on its own, from a handler that nothing registers in this file. The call resolves, but
    // the standard query has no source for the handler, so this query reports it.
    Ok(Response::with(response))
}
