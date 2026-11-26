use web_framework::prelude::*;

// Not an Iron program: the file does not use `iron`, and the crate that it imports from is not a
// dependency, so every call below has no target as well. The names are the same as in Iron, and the
// file must not be treated as one.

fn handler(req: &mut Request) -> Response {
    let res = req.url.path();
    let response = format!("<h1>{:?}</h1>", res);
    // GOOD for this query: the file does not use `iron`.
    Response::with((200, response))
}
