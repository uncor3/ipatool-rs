use crate::{
    appstore::types::App,
    constants::{ITUNES_API_LOOKUP, ITUNES_API_SEARCH},
    error::{IpaToolError, Result},
    http::client::Http,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ItunesSearchResponse {
    results: Vec<ItunesApp>,
}

#[derive(Debug, Deserialize)]
struct ItunesApp {
    #[serde(rename = "trackId")]
    track_id: Option<u64>,
    #[serde(rename = "bundleId")]
    bundle_id: Option<String>,
    #[serde(rename = "trackName")]
    track_name: Option<String>,
    #[serde(rename = "price")]
    price: Option<f64>,
    #[serde(rename = "trackPrice")]
    track_price: Option<f64>,
}

pub async fn search(http: &Http, term: &str, limit: u32) -> Result<Vec<App>> {
    let res = http
        .client()
        .get(ITUNES_API_SEARCH)
        .query(&[
            ("term", term),
            ("entity", "software"),
            ("limit", &limit.to_string()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<ItunesSearchResponse>()
        .await?;

    Ok(res
        .results
        .into_iter()
        .filter_map(|x| {
            Some(App {
                id: x.track_id?,
                bundle_id: x.bundle_id,
                name: x.track_name,
                price: x.price.or(x.track_price),
            })
        })
        .collect())
}

pub async fn lookup_by_bundle_id(http: &Http, bundle_id: &str) -> Result<App> {
    let res = http
        .client()
        .get(ITUNES_API_LOOKUP)
        .query(&[("bundleId", bundle_id), ("entity", "software")])
        .send()
        .await?
        .error_for_status()?
        .json::<ItunesSearchResponse>()
        .await?;

    let first = res
        .results
        .into_iter()
        .filter_map(|x| {
            Some(App {
                id: x.track_id?,
                bundle_id: x.bundle_id,
                name: x.track_name,
                price: x.price.or(x.track_price),
            })
        })
        .next()
        .ok_or_else(|| IpaToolError::NoApp)?;

    Ok(first)
}
