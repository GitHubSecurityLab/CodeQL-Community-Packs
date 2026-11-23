use axum::{http::HeaderValue, routing::get, Router};
use tower_http::cors::CorsLayer;

fn app() -> Router {
    Router::new().route("/json", get(|| async { "{}" })).layer(
        // BAD: any website can read responses from this service
        CorsLayer::new().allow_origin("*".parse::<HeaderValue>().unwrap()),
    )
}
