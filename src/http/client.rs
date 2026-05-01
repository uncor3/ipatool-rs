use crate::{
    constants::{APPSTORE_AUTH_URL, DEFAULT_USER_AGENT},
    error::Result,
    storage::cookies::PersistentCookies,
};
use reqwest::{Client, header, redirect::Policy};
use std::time::Duration;

#[derive(Clone)]
pub struct Http {
    client: Client,
    cookies: PersistentCookies,
}

impl Http {
    pub fn new(user_agent: String, cookies: PersistentCookies) -> Result<Self> {
        let jar = cookies.jar();

        let client = Client::builder()
            .user_agent(DEFAULT_USER_AGENT)
            .cookie_provider(jar)
            .user_agent(user_agent)
            .redirect(Policy::custom(|attempt| {
                // Mirror Go behavior: stop redirect chain if we just came from auth endpoint.
                if let Some(prev) = attempt.previous().last() {
                    if prev.as_str() == APPSTORE_AUTH_URL {
                        return attempt.stop();
                    }
                }
                attempt.follow()
            }))
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self { client, cookies })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn save_cookies(&self) -> Result<()> {
        self.cookies.save()
    }

    pub async fn get_bytes(&self, url: &str, headers: header::HeaderMap) -> Result<Vec<u8>> {
        let res = self.client.get(url).headers(headers).send().await?;
        let bytes = res.bytes().await?.to_vec();
        self.save_cookies().await?;
        Ok(bytes)
    }

    pub async fn post_form_bytes(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: header::HeaderMap,
    ) -> Result<(u16, header::HeaderMap, Vec<u8>)> {
        let res = self
            .client
            .post(url)
            .headers(headers)
            .form(form)
            .send()
            .await?;
        let status = res.status().as_u16();
        let hdrs = res.headers().clone();
        let bytes = res.bytes().await?.to_vec();
        self.save_cookies().await?;
        Ok((status, hdrs, bytes))
    }

    //FIXME
    pub async fn post_plist_bytes(
        &self,
        url: &str,
        plist_xml_body: Vec<u8>,
        headers: header::HeaderMap,
    ) -> Result<(u16, header::HeaderMap, Vec<u8>)> {
        let res = self
            .client
            .post(url)
            .headers(headers)
            .body(plist_xml_body)
            .send()
            .await?;
        let status = res.status().as_u16();
        let hdrs = res.headers().clone();
        let bytes = res.bytes().await?.to_vec();
        self.save_cookies().await?;
        Ok((status, hdrs, bytes))
    }
}
