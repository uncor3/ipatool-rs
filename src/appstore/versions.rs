use crate::appstore::types::{Account, App, ListVersionsResult};
use crate::constants::{PRIVATE_APPSTORE_DOMAIN, PRIVATE_DOWNLOAD_PATH};
use crate::http::client::Http;
use crate::{Result, http};
use plist::dictionary::Dictionary;
use reqwest;

fn create_list_version_req(
    acc: Account,
    app: App,
    guid: String,
    http: &Http,
) -> Result<reqwest::RequestBuilder> {
    let pod_prefix = match acc.pod {
        Some(p) => format!("p{}-", p),
        None => "".into(),
    };

    let url = format!(
        "https://{}{}{}?guid={}",
        pod_prefix, PRIVATE_APPSTORE_DOMAIN, PRIVATE_DOWNLOAD_PATH, guid
    );

    // let client = reqwest::Client::new();

    let mut payload = Dictionary::new();
    payload.insert("creditDisplay".into(), "".into());
    payload.insert("guid".into(), guid.into());
    payload.insert("salableAdamId".into(), app.id.into());

    let mut out = Vec::new();
    plist::to_writer_xml(&mut out, &plist::Value::Dictionary(payload))?;

    let req = http
        .client()
        .post(url)
        .body(out)
        .header("Content-Type", "application/x-apple-plist")
        .header("iCloud-DSID", &acc.directory_services_id)
        .header("X-Dsid", &acc.directory_services_id);

    Ok(req)
}

pub async fn list_versions(acc: Account, app: App, guid: String, http: &Http) -> Result<()> {
    let res = create_list_version_req(acc, app, guid, http)?
        .send()
        .await?;

    let string = res.bytes().await?;

    let debug = match std::str::from_utf8(&string) {
        Ok(s) => s,
        Err(_) => {
            println!("Error from_utf8");
            ""
        }
    };

    println!("{debug}");

    Ok(())

    // plist::from_bytes(res);
}
