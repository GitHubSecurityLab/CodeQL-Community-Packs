use warp::Filter;

// BAD: a URL path parameter is used as the host of an outbound request.
pub async fn bad_path_param() {
    let routes = warp::path::param().then(|tainted_param: String| async move {
        let response = reqwest::Client::new()
            .post(format!("https://{}", tainted_param)) // $ Alert
            .form(&[("one", "1")])
            .send()
            .await
            .expect("send");

        format!("{}", response.status())
    }); // $ Source (the source is the `then` closure, reported at its last line)

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

// BAD: a nested fixed-host template does not make the outer template safe.
pub async fn bad_nested_fixed_host_template() {
    let routes = warp::path::param().then(|tainted_param: String| async move {
        let response = reqwest::Client::new()
            .post(format!(
                "https://{}/{}",
                tainted_param,
                format!("https://my.app/{}", "constant")
            )) // $ Alert
            .send()
            .await
            .expect("send");

        format!("{}", response.status())
    }); // $ Source

    warp::serve(routes).run(([127, 0, 0, 1], 3032)).await;
}

// BAD: a nested `std::format!` with a fixed host does not make the outer template safe either.
pub async fn bad_nested_qualified_fixed_host_template() {
    let routes = warp::path::param().then(|tainted_param: String| async move {
        let response = reqwest::Client::new()
            .post(format!(
                "https://{}/{}",
                tainted_param,
                std::format!("https://my.app/{}", "constant")
            )) // $ Alert
            .send()
            .await
            .expect("send");

        format!("{}", response.status())
    }); // $ Source

    warp::serve(routes).run(([127, 0, 0, 1], 3035)).await;
}

// BAD: a nested `format_args!` with a fixed host does not make the outer template safe either.
pub async fn bad_nested_format_args_fixed_host_template() {
    let routes = warp::path::param().then(|tainted_param: String| async move {
        let response = reqwest::Client::new()
            .post(format!(
                "https://{}/{}",
                tainted_param,
                format_args!("https://my.app/{}", "constant")
            )) // $ Alert
            .send()
            .await
            .expect("send");

        format!("{}", response.status())
    }); // $ Source

    warp::serve(routes).run(([127, 0, 0, 1], 3038)).await;
}

// GOOD: the path parameter is only used in the path of a request to a fixed host.
pub async fn good_fixed_host() {
    let routes = warp::path::param().then(|tainted_param: String| async move {
        let response = reqwest::Client::new()
            .post(format!("https://my.app/{}", tainted_param))
            .send()
            .await
            .expect("send");

        format!("{}", response.status())
    });

    warp::serve(routes).run(([127, 0, 0, 1], 3031)).await;
}

// GOOD: overwriting the captured parameter with a fixed URL removes taint.
pub async fn good_overwrite_before_use() {
    let routes = warp::path::param().then(|mut tainted_param: String| async move {
        tainted_param = "https://my.app/".to_owned();

        let response = reqwest::Client::new()
            .post(tainted_param)
            .send()
            .await
            .expect("send");

        format!("{}", response.status())
    });

    warp::serve(routes).run(([127, 0, 0, 1], 3033)).await;
}

// GOOD: assigning the result of a fixed-host template removes taint.
pub async fn good_fixed_host_reassignment() {
    let routes = warp::path::param().then(|mut tainted_param: String| async move {
        tainted_param = format!("https://my.app/{}", tainted_param);

        let response = reqwest::Client::new()
            .post(tainted_param)
            .send()
            .await
            .expect("send");

        format!("{}", response.status())
    });

    warp::serve(routes).run(([127, 0, 0, 1], 3034)).await;
}

// GOOD: a fixed URL that is assigned before the `async` block is created replaces the parameter.
pub async fn good_overwrite_before_capture() {
    let routes = warp::path::param().then(|mut tainted_param: String| {
        tainted_param = "https://my.app/".to_owned();

        async move {
            let response = reqwest::Client::new()
                .post(tainted_param)
                .send()
                .await
                .expect("send");

            format!("{}", response.status())
        }
    });

    warp::serve(routes).run(([127, 0, 0, 1], 3036)).await;
}

// BAD: a value that is derived from the parameter before the `async` block is created is still tainted.
pub async fn bad_derived_before_capture() {
    let routes = warp::path::param().then(|mut tainted_param: String| {
        tainted_param = format!("https://{}", tainted_param);

        async move {
            let response = reqwest::Client::new()
                .post(tainted_param) // $ Alert
                .send()
                .await
                .expect("send");

            format!("{}", response.status())
        }
    }); // $ Source

    warp::serve(routes).run(([127, 0, 0, 1], 3037)).await;
}

// GOOD: a fixed URL that is assigned before the closure that creates the `async` block replaces the parameter.
pub async fn good_overwrite_before_nested_closure() {
    let routes = warp::path::param().then(|mut tainted_param: String| {
        tainted_param = "https://my.app/".to_owned();

        let request = move || async move {
            let response = reqwest::Client::new()
                .post(tainted_param)
                .send()
                .await
                .expect("send");

            format!("{}", response.status())
        };
        request()
    });

    warp::serve(routes).run(([127, 0, 0, 1], 3039)).await;
}

// BAD: a value that is derived from the parameter before the closure that creates the `async` block is still tainted.
pub async fn bad_derived_before_nested_closure() {
    let routes = warp::path::param().then(|mut tainted_param: String| {
        tainted_param = format!("https://{}", tainted_param);

        let request = move || async move {
            let response = reqwest::Client::new()
                .post(tainted_param) // $ Alert
                .send()
                .await
                .expect("send");

            format!("{}", response.status())
        };
        request()
    }); // $ Source

    warp::serve(routes).run(([127, 0, 0, 1], 3040)).await;
}
