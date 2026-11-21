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
