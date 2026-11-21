// Test cases for `rust/permissive-cors` (CWE-942).
//
// The third-party crates referenced here (warp, iron, tower-http, axum,
// actix-web, actix-cors, rocket, rocket_cors) are not fetched for this test,
// so the query must recognize the permissive CORS patterns syntactically.

mod warp_cors {
    use warp::Filter;

    pub async fn bad() {
        let cors = warp::cors()
            .allow_any_origin() // $ Alert
            .allow_methods(vec!["GET", "POST"])
            .allow_headers(vec!["Content-Type", "Authorization"]);

        let route = warp::path("example")
            .and(warp::get())
            .map(|| "Hello, CORS!")
            .with(cors);

        warp::serve(route).run(([127, 0, 0, 1], 3030)).await;
    }

    pub async fn bad_raw_header() {
        let route = warp::path("example")
            .map(|| "Hello, CORS!")
            .with(warp::reply::with::header("Access-Control-Allow-Origin", "*")); // $ Alert
        warp::serve(route).run(([127, 0, 0, 1], 3031)).await;
    }

    pub async fn good() {
        let cors = warp::cors()
            .allow_origin("https://trusted.example.com")
            .allow_methods(vec!["GET", "POST"]);

        let route = warp::path("example")
            .map(|| "Hello, CORS!")
            .with(cors);

        warp::serve(route).run(([127, 0, 0, 1], 3032)).await;
    }

    pub async fn good_raw_header() {
        let route = warp::path("example")
            .map(|| "Hello, CORS!")
            .with(warp::reply::with::header(
                "Access-Control-Allow-Origin",
                "https://trusted.example.com",
            ));
        warp::serve(route).run(([127, 0, 0, 1], 3033)).await;
    }
}

mod iron_cors {
    use iron::headers::AccessControlAllowOrigin;
    use iron::prelude::*;
    use iron::status;

    pub fn bad() {
        Iron::new(|_: &mut Request| {
            let mut r = Response::with((status::Ok, "Hello World!"));
            r.headers.set(AccessControlAllowOrigin::Any); // $ Alert
            Ok(r)
        })
        .http("localhost:8080")
        .unwrap();
    }

    pub fn good() {
        Iron::new(|_: &mut Request| {
            let mut r = Response::with((status::Ok, "Hello World!"));
            r.headers.set(AccessControlAllowOrigin::Value(
                "https://trusted.example.com".to_owned(),
            ));
            Ok(r)
        })
        .http("localhost:8081")
        .unwrap();
    }
}

mod tower_http_cors {
    use std::str::FromStr;

    use axum::{
        http::{header, HeaderMap, HeaderValue, Method},
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use tower_http::cors::{self, AllowOrigin, Any, CorsLayer};

    async fn json() -> impl IntoResponse {
        Json(vec!["one", "two", "three"])
    }

    pub fn bad_parsed_wildcard() -> Router {
        Router::new().route("/json", get(json)).layer(
            CorsLayer::new()
                .allow_origin("*".parse::<HeaderValue>().unwrap()) // $ Alert
                .allow_methods([Method::GET]),
        )
    }

    pub fn bad_from_static_wildcard() -> Router {
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::new().allow_origin(HeaderValue::from_static("*"))) // $ Alert
    }

    pub fn bad_any() -> Router {
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::new().allow_origin(Any)) // $ Alert
    }

    pub fn bad_qualified_any() -> Router {
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::new().allow_origin(cors::Any)) // $ Alert
    }

    pub fn bad_allow_origin_any() -> Router {
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::new().allow_origin(AllowOrigin::any())) // $ Alert
    }

    pub fn bad_mirror_request() -> Router {
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::new().allow_origin(AllowOrigin::mirror_request())) // $ Alert
    }

    pub fn bad_wildcard_variable() -> Router {
        let origin = "*";
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::new().allow_origin(origin.parse::<HeaderValue>().unwrap())) // $ Alert
    }

    pub fn bad_reassigned_wildcard_variable() -> Router {
        let mut origin = "https://trusted.example.com";
        origin = "*";
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::new().allow_origin(origin.parse::<HeaderValue>().unwrap())) // $ Alert
    }

    pub fn good_reassigned_trusted_variable() -> Router {
        let mut origin = "*";
        origin = "https://trusted.example.com";
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::new().allow_origin(origin.parse::<HeaderValue>().unwrap()))
    }

    pub fn bad_permissive() -> Router {
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::permissive()) // $ Alert
    }

    pub fn bad_very_permissive() -> Router {
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::very_permissive()) // $ Alert
    }

    pub async fn bad_raw_header_map() -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*")); // $ Alert
        (headers, "Hello")
    }

    pub async fn bad_raw_header_tuple() -> impl IntoResponse {
        ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], "Hello") // $ Alert
    }

    pub fn good_exact_origin() -> Router {
        Router::new().route("/json", get(json)).layer(
            CorsLayer::new()
                .allow_origin("https://trusted.example.com".parse::<HeaderValue>().unwrap())
                .allow_methods([Method::GET])
                .allow_headers(Any),
        )
    }

    pub fn good_origin_list() -> Router {
        Router::new().route("/json", get(json)).layer(
            CorsLayer::new().allow_origin(AllowOrigin::list([
                HeaderValue::from_static("https://a.example.com"),
                HeaderValue::from_static("https://b.example.com"),
            ])),
        )
    }

    pub fn good_any_methods_only() -> Router {
        Router::new()
            .route("/json", get(json))
            .layer(CorsLayer::new().allow_methods(Any).allow_headers(Any))
    }

    pub async fn good_raw_header_map() -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("https://trusted.example.com"),
        );
        headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("*"));
        (headers, "Hello")
    }

    pub async fn bad_raw_header_name_constructor() -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("access-control-allow-origin"),
            HeaderValue::from_static("*"),
        ); // $ Alert
        (headers, "Hello")
    }

    pub async fn bad_raw_header_name_constructor_unwrap() -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_str("access-control-allow-origin").unwrap(),
            HeaderValue::from_static("*"),
        ); // $ Alert
        (headers, "Hello")
    }

    pub async fn bad_raw_header_name_constructor_try(
    ) -> Result<impl IntoResponse, Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_str("access-control-allow-origin")?,
            HeaderValue::from_static("*"),
        ); // $ Alert
        Ok((headers, "Hello"))
    }

    fn check(value: Option<&HeaderValue>, expected: &str) -> bool {
        value.map_or(false, |v| v == expected)
    }

    // Reading (rather than setting) the header must not be reported.
    pub fn good_read_header(headers: &HeaderMap) {
        assert_eq!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
        assert!(check(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN), "*"));
    }
}

mod actix_cors_example {
    use actix_cors::Cors;
    use actix_web::{web, App, HttpResponse, HttpServer};

    async fn index() -> HttpResponse {
        HttpResponse::Ok().body("Hello")
    }

    async fn bad_insert_header() -> HttpResponse {
        HttpResponse::Ok()
            .insert_header(("Access-Control-Allow-Origin", "*")) // $ Alert
            .body("Hello")
    }

    async fn good_insert_header() -> HttpResponse {
        HttpResponse::Ok()
            .insert_header(("access-control-allow-origin", "https://trusted.example.com"))
            .insert_header(("X-Custom", "*"))
            .body("Hello")
    }

    pub async fn run() -> std::io::Result<()> {
        HttpServer::new(|| {
            let bad = Cors::default().allow_any_origin(); // $ Alert
            let bad_permissive = Cors::permissive(); // $ Alert
            let good = Cors::default()
                .allowed_origin("https://trusted.example.com")
                .allow_any_method()
                .allow_any_header();
            App::new()
                .wrap(bad)
                .wrap(bad_permissive)
                .wrap(good)
                .route("/", web::get().to(index))
                .route("/bad", web::get().to(bad_insert_header))
                .route("/good", web::get().to(good_insert_header))
        })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
    }
}

mod rocket_cors_example {
    use rocket_cors::{AllowedOrigins, CorsOptions};

    pub fn bad() -> CorsOptions {
        CorsOptions {
            allowed_origins: AllowedOrigins::all(), // $ Alert
            ..Default::default()
        }
    }

    pub fn good() -> CorsOptions {
        CorsOptions {
            allowed_origins: AllowedOrigins::some_exact(&["https://trusted.example.com"]),
            ..Default::default()
        }
    }
}

fn main() {}
