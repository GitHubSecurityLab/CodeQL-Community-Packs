use axum::{http::HeaderValue, routing::get, Router};
use tower_http::cors::CorsLayer;

fn app() -> Router {
    Router::new().route("/json", get(|| async { "{}" })).layer(
        // GOOD: only the trusted front-end origin can read responses
        CorsLayer::new().allow_origin("https://app.example.com".parse::<HeaderValue>().unwrap()),
    )
}
