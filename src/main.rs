use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts, Query, State},
    http::{request::Parts, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use axum_extra::extract::{
    cookie::{Cookie, CookieJar, SameSite},
    Form,
};
use axum_template::RenderHtml;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use minijinja::context as template_context;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::JwkEcKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;
use std::{env, ops::Deref, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use unic_langid::LanguageIdentifier;
use xml_builder::{XMLBuilder, XMLElement};

use ttf_parser::Face;

use axum_template::engine::Engine;

#[cfg(feature = "reload")]
use minijinja_autoreload::AutoReloader;

#[cfg(feature = "embed")]
use minijinja::Environment;

#[cfg(feature = "embed")]
pub(crate) type AppEngine = Engine<Environment<'static>>;

const FONT_DATA: &[u8] = include_bytes!(env!("FONT_PATH"));

#[cfg(feature = "reload")]
pub(crate) type AppEngine = Engine<AutoReloader>;

// Make our own error that wraps `anyhow::Error`.
#[derive(thiserror::Error, Debug)]
pub enum BlueBadgeError {
    #[error("ERR-XXX Invalid Language")]
    InvalidLanguage(),

    #[error("An error occurred: {0}")]
    Anyhow(#[from] anyhow::Error),
}

impl IntoResponse for BlueBadgeError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {:?}", self),
        )
            .into_response()
    }
}

pub struct InnerWebContext {
    pub engine: AppEngine,
    pub http_client: reqwest::Client,
    pub font: ttf_parser::Face<'static>,
    pub fontdb: Arc<fontdb::Database>,
    pub supported_languages: Vec<LanguageIdentifier>,
}

impl Deref for WebContext {
    type Target = InnerWebContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, FromRef)]
pub struct WebContext(pub Arc<InnerWebContext>);

#[cfg(feature = "reload")]
pub mod reload_env {
    use std::path::PathBuf;

    use minijinja::{path_loader, Environment};
    use minijinja_autoreload::AutoReloader;

    pub fn build_env(http_external: &str) -> AutoReloader {
        let http_external = http_external.to_string();
        AutoReloader::new(move |notifier| {
            let template_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates");
            let mut env = Environment::new();
            env.set_trim_blocks(true);
            env.set_lstrip_blocks(true);
            env.add_global("external_base", http_external.clone());
            env.set_loader(path_loader(&template_path));
            notifier.set_fast_reload(true);
            notifier.watch_path(&template_path, true);
            Ok(env)
        })
    }
}

#[cfg(feature = "embed")]
pub mod embed_env {
    use minijinja::Environment;

    pub fn build_env(http_external: String) -> Environment<'static> {
        let mut env = Environment::new();
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.add_global("external_base", http_external.clone());
        minijinja_embed::load_templates!(&mut env);
        env
    }
}

#[derive(Clone)]
pub struct AcceptedLanguage {
    pub value: String,
    pub quality: f32,
}

impl Eq for AcceptedLanguage {}

impl PartialEq for AcceptedLanguage {
    fn eq(&self, other: &Self) -> bool {
        self.quality == other.quality && self.value.eq(&other.value)
    }
}

impl PartialOrd for AcceptedLanguage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AcceptedLanguage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.quality > other.quality {
            std::cmp::Ordering::Greater
        } else if self.quality < other.quality {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    }
}

impl FromStr for AcceptedLanguage {
    type Err = BlueBadgeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut value = s.trim().split(';');
        let (value, quality) = (value.next(), value.next());

        let Some(value) = value else {
            return Err(BlueBadgeError::InvalidLanguage());
        };

        if value.is_empty() {
            return Err(BlueBadgeError::InvalidLanguage());
        }

        let quality = if let Some(quality) = quality.and_then(|q| q.strip_prefix("q=")) {
            quality.parse::<f32>().unwrap_or(0.0)
        } else {
            1.0
        };

        Ok(AcceptedLanguage {
            value: value.to_string(),
            quality,
        })
    }
}

pub struct Language(pub LanguageIdentifier);

#[async_trait]
impl<S> FromRequestParts<S> for Language
where
    WebContext: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = BlueBadgeError;

    async fn from_request_parts(parts: &mut Parts, context: &S) -> Result<Self, Self::Rejection> {
        let web_context = WebContext::from_ref(context);

        let cookie_jar = CookieJar::from_headers(&parts.headers);

        if let Some(lang_cookie) = cookie_jar.get("lang") {
            for value_part in lang_cookie.value().split(',') {
                tracing::debug!("lang cookie value part: {:?}", value_part);
                if let Ok(value) = value_part.parse::<LanguageIdentifier>() {
                    for lang in &web_context.supported_languages {
                        if lang.matches(&value, true, false) {
                            return Ok(Self(lang.clone()));
                        }
                    }
                }
            }
        }

        let accept_languages = &mut parts
            .headers
            .get("accept-language")
            .and_then(|header| header.to_str().ok())
            .map(|header| {
                header
                    .split(',')
                    .filter_map(|lang| lang.parse::<AcceptedLanguage>().ok())
                    .collect::<Vec<AcceptedLanguage>>()
            })
            .unwrap_or_default();

        accept_languages.sort();

        for accept_language in accept_languages {
            if let Ok(value) = accept_language.value.parse::<LanguageIdentifier>() {
                tracing::debug!("accept language value part: {:?}", value);
                for lang in &web_context.supported_languages {
                    if lang.matches(&value, true, false) {
                        return Ok(Self(lang.clone()));
                    }
                }
            }
        }

        Ok(Self(web_context.supported_languages[0].clone()))
    }
}

#[derive(Serialize)]
struct Message {
    pub style: String,
    pub header: Option<String>,
    pub content: String,
}

impl Message {
    pub fn danger(header: Option<&str>, content: &str) -> Self {
        Self {
            style: "is-danger".to_string(),
            header: header.map(|s| s.to_string()),
            content: content.to_string(),
        }
    }

    pub fn success(header: Option<&str>, content: &str) -> Self {
        Self {
            style: "is-success".to_string(),
            header: header.map(|s| s.to_string()),
            content: content.to_string(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlcService {
    pub id: String,

    #[serde(rename = "type")]
    pub service_type: String,

    pub service_endpoint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveDid {
    pub id: String,
    pub also_known_as: Vec<String>,
    pub service: Vec<PlcService>,
}

pub fn split_at_uri(uri: &str) -> Result<[&str; 3]> {
    let stripped = uri.strip_prefix("at://");
    if stripped.is_none() {
        return Err(anyhow!("invalid URI"));
    }
    let uri: &str = stripped.unwrap();

    let mut components = uri.split('/');
    let did = components.next().ok_or(anyhow!("missing did"))?;

    validate_did(did)?;

    let collection = components.next().ok_or(anyhow!("missing collection"))?;

    let rkey = components.next().ok_or(anyhow!("missing rkey"))?;

    if components.next().is_some() {
        return Err(anyhow!("unexpected URI components"));
    }

    Ok([did, collection, rkey])
}

fn validate_did(did: &str) -> Result<()> {
    if !did.starts_with("did:plc:") {
        Err(anyhow!("Only PLC DIDs are supported at this time."))?;
    }
    Ok(())
}

async fn pds_for_did(http_client: reqwest::Client, did: &str) -> Result<(String, Vec<String>)> {
    let destination = format!("https://plc.directory/{}", did);
    tracing::debug!("GET: {:?}", destination);

    let did_content: ResolveDid = http_client
        .get(destination)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .context(anyhow!("error getting DID info from PDS"))?
        .json()
        .await
        .context(anyhow!("parsing DID info from PDS"))?;

    let service_endpoint = did_content
        .service
        .first()
        .map(|service| service.service_endpoint.clone())
        .ok_or_else(|| anyhow!("DID has no PDS records"))?;

    let mut good_prefixes = vec![];

    for aka in did_content.also_known_as {
        good_prefixes.push(aka.replace("at://", "https://"));
    }

    for service in did_content.service {
        good_prefixes.push(service.service_endpoint);
    }

    Ok((service_endpoint, good_prefixes))
}

pub mod datetime_format {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = date.to_rfc3339_opts(SecondsFormat::Millis, true);
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let date_value = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&date_value)
            .map(|v| v.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "$type")]
pub enum ProofWrapper {
    #[serde(rename = "blue.badge.proof")]
    Proof(Proof),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Proof {
    #[serde(rename = "k")]
    pub key: String,
    #[serde(rename = "s")]
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BadgeRef {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "$type")]
pub enum AwardWrapper {
    #[serde(rename = "blue.badge.award")]
    Award(Award),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Award {
    pub did: String,
    pub badge: BadgeRef,
    #[serde(with = "datetime_format")]
    pub issued: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof: Option<Proof>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum RecordType {
    Award(AwardWrapper),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GetRecordResponse {
    pub uri: String,
    pub cid: String,

    pub value: RecordType,
}

async fn handle_index(
    State(web_context): State<WebContext>,
    Language(language): Language,
) -> Result<impl IntoResponse, BlueBadgeError> {
    Ok(RenderHtml(
        "index.html",
        web_context.engine.clone(),
        template_context! {
            language => language.to_string(),
        },
    )
    .into_response())
}

pub type QueryParam<'a> = (&'a str, &'a str);
pub type QueryParams<'a> = Vec<QueryParam<'a>>;

pub fn stringify(query: QueryParams) -> String {
    query.iter().fold(String::new(), |acc, &tuple| {
        acc + tuple.0 + "=" + tuple.1 + "&"
    })
}

async fn get_record(
    http_client: reqwest::Client,
    pds: &str,
    did: &str,
    collection: &str,
    rkey: &str,
) -> Result<GetRecordResponse> {
    let args = vec![("repo", did), ("collection", collection), ("rkey", rkey)];
    let destination = format!(
        "{}/xrpc/com.atproto.repo.getRecord?{}",
        pds,
        stringify(args)
    );

    tracing::debug!("GET: {:?}", destination);

    http_client
        .get(destination)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .context(anyhow!("error getting DID info from PDS"))?
        .json()
        .await
        .context(anyhow!("parsing DID info from PDS"))
}

#[derive(Deserialize, Clone)]
pub struct WrappedJsonWebKey {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<String>,

    #[serde(flatten)]
    pub jwk: JwkEcKey,
}

#[derive(Deserialize, Clone)]
pub struct WrappedJsonWebKeySet {
    pub keys: Vec<WrappedJsonWebKey>,
}

async fn public_key_for_jwk_uri(
    http_client: reqwest::Client,
    jwk_url: &str,
    good_prefixes: &Vec<String>,
) -> Result<p256::PublicKey> {
    let (destination, key_id) = jwk_url
        .split_once('#')
        .context(anyhow!("invalid JWK URL"))?;

    if !good_prefixes
        .iter()
        .any(|prefix| destination.starts_with(prefix))
    {
        return Err(anyhow!(
            "jwk url does not match any prefix: {:?}",
            good_prefixes
        ));
    }

    tracing::debug!("GET: {:?}", destination);

    let jwks: WrappedJsonWebKeySet = http_client
        .get(destination)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .context(anyhow!("error getting DID info from PDS"))?
        .json()
        .await
        .context(anyhow!("parsing DID info from PDS"))?;

    let found_key = jwks
        .keys
        .iter()
        .find(|k| k.kid.as_deref() == Some(key_id))
        .ok_or(anyhow!("key not found"))?
        .clone();

    p256::PublicKey::from_jwk(&found_key.jwk).map_err(|err| anyhow!("invalid JWK: {:?}", err))
}

pub fn verify_badge_signature(
    key_id: &str,
    public_key: &p256::PublicKey,
    badge: &Award,
) -> Result<()> {
    let proof = badge
        .proof
        .clone()
        .ok_or_else(|| anyhow!("signature is missing"))?;

    if proof.key != key_id {
        return Err(anyhow!("key_id does not match"));
    }

    let mut scrubbed_badge = badge.clone();
    scrubbed_badge.proof = None;

    let serialized_badge = serde_ipld_dagcbor::to_vec(&AwardWrapper::Award(scrubbed_badge))
        .context(anyhow!("unable to serialize award"))?;

    let verifying_key = VerifyingKey::from(public_key);

    let decoded_signature = general_purpose::URL_SAFE
        .decode(proof.signature)
        .context(anyhow!("unable to base64 decode award proof signature"))?;

    let p256_signature = Signature::from_slice(&decoded_signature)
        .map_err(|err| anyhow!("unable to create signature: {:?}", err))?;

    verifying_key
        .verify(&serialized_badge, &p256_signature)
        .map_err(|err| anyhow!("signature verification failed: {:?}", err))?;

    Ok(())
}

#[derive(Deserialize, Default)]
pub struct VerifyRequest {
    pub uri: Option<String>,
}

#[derive(Serialize)]
struct VerifiedBadge {
    at_uri: String,
    cid: String,
    issuer_did: String,
    issuer_handle: String,
    subject_did: String,
    subject_handle: String,
    badge_display_text: String,
    record: GetRecordResponse,
}

async fn verify_badge(
    http_client: reqwest::Client,
    uri: &str,
) -> Result<VerifiedBadge, BlueBadgeError> {
    let [did, collection, rkey] = split_at_uri(uri)?;

    let (pds, handles) = pds_for_did(http_client.clone(), did).await?;

    let record = get_record(http_client.clone(), &pds, did, collection, rkey).await?;

    let RecordType::Award(AwardWrapper::Award(award)) = record.value.clone();

    if award.proof.is_none() {
        return Err(anyhow!("record has no proof").into());
    }

    let [issuer_did, badge_collection, _] = split_at_uri(&award.badge.uri)?;

    if validate_did(issuer_did).is_err() {
        return Err(anyhow!("invalid badge DID").into());
    }

    if badge_collection != "blue.badge.definition" {
        return Err(anyhow!("invalid badge collection").into());
    }

    let (_, issuer_handles) = pds_for_did(http_client.clone(), issuer_did).await?;

    let public_key = public_key_for_jwk_uri(
        http_client.clone(),
        &award.proof.clone().unwrap().key,
        &issuer_handles,
    )
    .await?;

    let issuer_handle = issuer_handles
        .first()
        .map(|value| value.to_string())
        .unwrap_or_default();
    let subject_handle = handles
        .first()
        .map(|value| value.to_string())
        .unwrap_or_default();

    verify_badge_signature(&award.proof.clone().unwrap().key, &public_key, &award)?;

    Ok(VerifiedBadge {
        at_uri: uri.to_string(),
        cid: record.cid.clone(),
        issuer_did: issuer_did.to_string(),
        issuer_handle,
        subject_did: did.to_string(),
        subject_handle,
        badge_display_text: award.badge.name.unwrap_or(award.badge.uri),
        record,
    })
}

async fn handle_verify(
    State(web_context): State<WebContext>,
    verify_request: Query<VerifyRequest>,
) -> Result<impl IntoResponse, BlueBadgeError> {
    let uri = verify_request.uri.clone();

    if uri.is_none() {
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "No uri query string parameter provided.")],
            },
        )
        .into_response());
    }

    let uri = uri.unwrap();

    let verified_badge = verify_badge(web_context.http_client.clone(), &uri).await;

    if let Err(err) = verified_badge {
        tracing::error!("error verifying badge: {:?}", err);
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, &format!("Unable to verify record: {}", err))],
                uri
            },
        )
        .into_response());
    }

    let verified_badge = verified_badge.unwrap();

    Ok(RenderHtml(
        "verify.html",
        web_context.engine.clone(),
        template_context! {
            messages => vec![Message::success(None, "Record is valid!")],
            uri, verified_badge,
        },
    )
    .into_response())
}

pub fn face_text_size(face: &Face, text: &str, font_size: f32) -> (f32, f32) {
    let units_per_em = face.units_per_em() as f32;
    let scale_factor = font_size / units_per_em;

    let width = text
        .chars()
        .filter_map(|ch| {
            face.glyph_index(ch)
                .and_then(|glyph_id| face.glyph_hor_advance(glyph_id))
        })
        .map(|advance| advance as f32 * scale_factor)
        .sum::<f32>();

    let ascender = face.ascender() as f32 * scale_factor;
    let descender = face.descender() as f32 * scale_factor;
    let height = (ascender - descender).abs();

    (width, height)
}

pub fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        None => s,
        Some((idx, _)) => &s[..idx],
    }
}

fn render_error_svg(
    font: &ttf_parser::Face<'static>,
    raw_message: &str,
) -> Result<Vec<u8>, BlueBadgeError> {
    let message = ammonia::Builder::new()
        .tags(HashSet::new())
        .clean(raw_message)
        .to_string();

    let display_message = truncate(&message, 50);
    let display_message_width = {
        let (width, _height) = face_text_size(font, display_message, 12.0);
        (width + 13.0).round_ties_even()
    };

    let mut xml = XMLBuilder::new().standalone(Some(true)).build();

    let mut svg = XMLElement::new("svg");
    svg.add_attribute("xmlns", "http://www.w3.org/2000/svg");
    svg.add_attribute("xmlns:xlink", "http://www.w3.org/1999/xlink");
    svg.add_attribute("width", &format!("{}", display_message_width));
    svg.add_attribute("height", "20");

    let mut title_element = XMLElement::new("title");
    title_element
        .add_text(display_message.to_string())
        .context(anyhow!("unable to generate svg"))?;

    svg.add_child(title_element)
        .context(anyhow!("unable to generate svg"))?;

    let linear_gradient = {
        let mut background = XMLElement::new("linearGradient");
        background.add_attribute("id", "smooth");
        background.add_attribute("x2", "0");
        background.add_attribute("y2", "100%");

        let mut background_stop1 = XMLElement::new("stop");
        background_stop1.add_attribute("offset", "0");
        background_stop1.add_attribute("stop-color", "#bbb"); // grey
        background_stop1.add_attribute("stop-opacity", ".1");

        let mut background_stop2 = XMLElement::new("stop");
        background_stop2.add_attribute("offset", "1");
        background_stop2.add_attribute("stop-opacity", ".1");

        background
            .add_child(background_stop1)
            .context(anyhow!("unable to generate svg"))?;
        background
            .add_child(background_stop2)
            .context(anyhow!("unable to generate svg"))?;
        background
    };

    svg.add_child(linear_gradient)
        .context(anyhow!("unable to generate svg"))?;

    let mask = {
        let mut mask_parent = XMLElement::new("mask");
        mask_parent.add_attribute("id", "round");

        let mut mask_rect = XMLElement::new("rect");
        mask_rect.add_attribute("width", &format!("{}", display_message_width));
        mask_rect.add_attribute("height", "20");
        mask_rect.add_attribute("rx", "3");
        mask_rect.add_attribute("fill", "#fff"); // white

        mask_parent
            .add_child(mask_rect)
            .context(anyhow!("unable to generate svg"))?;

        mask_parent
    };

    svg.add_child(mask)
        .context(anyhow!("unable to generate svg"))?;

    let group_one = {
        let mut group1 = XMLElement::new("g");
        group1.add_attribute("mask", "url(#round)");

        let mut group1_rect = XMLElement::new("rect");
        group1_rect.add_attribute("width", &format!("{}", display_message_width));
        group1_rect.add_attribute("height", "20");
        group1_rect.add_attribute("fill", "#e05d44"); // Danger Red

        group1
            .add_child(group1_rect)
            .context(anyhow!("unable to generate svg"))?;

        let mut group4_rect = XMLElement::new("rect");
        group4_rect.add_attribute("width", &format!("{}", display_message_width));
        group4_rect.add_attribute("height", "20");
        group4_rect.add_attribute("fill", "url(#smooth)");

        group1
            .add_child(group4_rect)
            .context(anyhow!("unable to generate svg"))?;
        group1
    };

    svg.add_child(group_one)
        .context(anyhow!("unable to generate svg"))?;

    let group_two = {
        let mut group2 = XMLElement::new("g");
        group2.add_attribute("fill", "#fff");
        group2.add_attribute("text-anchor", "middle");
        group2.add_attribute(
            "font-family",
            "DejaVuSansM Nerd Font,DejaVu Sans,Verdana,Geneva,sans-serif",
        );
        group2.add_attribute("font-size", "12");

        let mut group2_text1 = XMLElement::new("text");
        group2_text1.add_attribute("x", &format!("{}", (display_message_width / 2.0)));
        group2_text1.add_attribute("y", "15");
        group2_text1.add_attribute("fill", "#010101");
        group2_text1.add_attribute("fill-opacity", ".3");
        group2_text1
            .add_text(display_message.to_string())
            .context(anyhow!("unable to generate svg"))?;

        group2
            .add_child(group2_text1)
            .context(anyhow!("unable to generate svg"))?;

        let mut group2_text2 = XMLElement::new("text");
        group2_text2.add_attribute("x", &format!("{}", (display_message_width / 2.0)));
        group2_text2.add_attribute("y", "14");
        group2_text2
            .add_text(display_message.to_string())
            .context(anyhow!("unable to generate svg"))?;

        group2
            .add_child(group2_text2)
            .context(anyhow!("unable to generate svg"))?;

        group2
    };
    svg.add_child(group_two)
        .context(anyhow!("unable to generate svg"))?;

    xml.set_root_element(svg);

    let mut xml_buffer: Vec<u8> = Vec::new();
    xml.generate(&mut xml_buffer)
        .context(anyhow!("unable to generate svg"))?;

    Ok(xml_buffer)
}

fn render_award_svg(
    font: &ttf_parser::Face<'static>,
    raw_issuer_label: &str,
    raw_subject_label: &str,
    raw_badge_label: &str,
) -> Result<Vec<u8>, BlueBadgeError> {
    let issuer_label = ammonia::Builder::new()
        .tags(HashSet::new())
        .clean(raw_issuer_label)
        .to_string();
    let subject_label = ammonia::Builder::new()
        .tags(HashSet::new())
        .clean(raw_subject_label)
        .to_string();
    let badge_label = ammonia::Builder::new()
        .tags(HashSet::new())
        .clean(raw_badge_label)
        .to_string();

    let display_issuer_label = truncate(&issuer_label, 50);
    let display_subject_label = truncate(&subject_label, 50);
    let display_badge_label = truncate(&badge_label, 50);

    let title = format!("{} {} {}", issuer_label, subject_label, badge_label);

    let issuer_width = {
        let (width, _height) = face_text_size(font, display_issuer_label, 12.0);
        (width + 13.0).round_ties_even()
    };

    let subject_width = {
        let (width, _height) = face_text_size(font, display_subject_label, 12.0);
        (width + 13.0).round_ties_even()
    };

    let badge_width = {
        let (width, _height) = face_text_size(font, display_badge_label, 12.0);
        (width + 13.0).round_ties_even()
    };

    let full_width = issuer_width + subject_width + badge_width;

    let mut xml = XMLBuilder::new().standalone(Some(true)).build();

    let mut svg = XMLElement::new("svg");
    svg.add_attribute("xmlns", "http://www.w3.org/2000/svg");
    svg.add_attribute("xmlns:xlink", "http://www.w3.org/1999/xlink");
    svg.add_attribute("width", &format!("{}", full_width));
    svg.add_attribute("height", "20");

    let mut title_element = XMLElement::new("title");
    title_element
        .add_text(title.to_string())
        .context(anyhow!("unable to generate svg"))?;

    svg.add_child(title_element)
        .context(anyhow!("unable to generate svg"))?;

    let linear_gradient = {
        let mut background = XMLElement::new("linearGradient");
        background.add_attribute("id", "smooth");
        background.add_attribute("x2", "0");
        background.add_attribute("y2", "100%");

        let mut background_stop1 = XMLElement::new("stop");
        background_stop1.add_attribute("offset", "0");
        background_stop1.add_attribute("stop-color", "#bbb"); // grey
        background_stop1.add_attribute("stop-opacity", ".1");

        let mut background_stop2 = XMLElement::new("stop");
        background_stop2.add_attribute("offset", "1");
        background_stop2.add_attribute("stop-opacity", ".1");

        background
            .add_child(background_stop1)
            .context(anyhow!("unable to generate svg"))?;
        background
            .add_child(background_stop2)
            .context(anyhow!("unable to generate svg"))?;
        background
    };

    svg.add_child(linear_gradient)
        .context(anyhow!("unable to generate svg"))?;

    let mask = {
        let mut mask_parent = XMLElement::new("mask");
        mask_parent.add_attribute("id", "round");

        let mut mask_rect = XMLElement::new("rect");
        mask_rect.add_attribute("width", &format!("{}", full_width));
        mask_rect.add_attribute("height", "20");
        mask_rect.add_attribute("rx", "3");
        mask_rect.add_attribute("fill", "#fff"); // white

        mask_parent
            .add_child(mask_rect)
            .context(anyhow!("unable to generate svg"))?;

        mask_parent
    };

    svg.add_child(mask)
        .context(anyhow!("unable to generate svg"))?;

    let group_one = {
        let mut group1 = XMLElement::new("g");
        group1.add_attribute("mask", "url(#round)");

        let mut group1_rect = XMLElement::new("rect");
        group1_rect.add_attribute("width", &format!("{}", issuer_width));
        group1_rect.add_attribute("height", "20");
        group1_rect.add_attribute("fill", "#555"); // Dark grey

        group1
            .add_child(group1_rect)
            .context(anyhow!("unable to generate svg"))?;

        let mut group2_rect = XMLElement::new("rect");
        group2_rect.add_attribute("width", &format!("{}", subject_width));
        group2_rect.add_attribute("height", "20");
        group2_rect.add_attribute("fill", "#4c1"); // Success Green
        group2_rect.add_attribute("x", &format!("{}", issuer_width));

        group1
            .add_child(group2_rect)
            .context(anyhow!("unable to generate svg"))?;

        let mut group3_rect = XMLElement::new("rect");
        group3_rect.add_attribute("width", &format!("{}", badge_width));
        group3_rect.add_attribute("height", "20");
        group3_rect.add_attribute("fill", "#007ec6"); // Dark blue
        group3_rect.add_attribute("x", &format!("{}", issuer_width + subject_width));

        group1
            .add_child(group3_rect)
            .context(anyhow!("unable to generate svg"))?;

        let mut group4_rect = XMLElement::new("rect");
        group4_rect.add_attribute("width", &format!("{}", full_width));
        group4_rect.add_attribute("height", "20");
        group4_rect.add_attribute("fill", "url(#smooth)");

        group1
            .add_child(group4_rect)
            .context(anyhow!("unable to generate svg"))?;
        group1
    };

    svg.add_child(group_one)
        .context(anyhow!("unable to generate svg"))?;

    let group_two = {
        let mut group2 = XMLElement::new("g");
        group2.add_attribute("fill", "#fff");
        group2.add_attribute("text-anchor", "middle");
        group2.add_attribute(
            "font-family",
            "DejaVuSansM Nerd Font,DejaVu Sans,Verdana,Geneva,sans-serif",
        );
        group2.add_attribute("font-size", "12");

        let mut group2_text1 = XMLElement::new("text");
        group2_text1.add_attribute("x", &format!("{}", (issuer_width / 2.0)));
        group2_text1.add_attribute("y", "15");
        group2_text1.add_attribute("fill", "#010101");
        group2_text1.add_attribute("fill-opacity", ".3");
        group2_text1
            .add_text(issuer_label.to_string())
            .context(anyhow!("unable to generate svg"))?;

        group2
            .add_child(group2_text1)
            .context(anyhow!("unable to generate svg"))?;

        let mut group2_text2 = XMLElement::new("text");
        group2_text2.add_attribute("x", &format!("{}", (issuer_width / 2.0)));
        group2_text2.add_attribute("y", "14");
        group2_text2
            .add_text(issuer_label.to_string())
            .context(anyhow!("unable to generate svg"))?;

        group2
            .add_child(group2_text2)
            .context(anyhow!("unable to generate svg"))?;

        let mut group2_text3 = XMLElement::new("text");
        group2_text3.add_attribute("x", &format!("{}", issuer_width + (subject_width / 2.0)));
        group2_text3.add_attribute("y", "15");
        // group2_text3.add_attribute("fill", "#010101");
        group2_text3.add_attribute("fill", "#000");
        group2_text3.add_attribute("fill-opacity", ".3");
        group2_text3
            .add_text(subject_label.to_string())
            .context(anyhow!("unable to generate svg"))?;

        group2
            .add_child(group2_text3)
            .context(anyhow!("unable to generate svg"))?;

        let mut group2_text4 = XMLElement::new("text");
        group2_text4.add_attribute("x", &format!("{}", issuer_width + (subject_width / 2.0)));
        group2_text4.add_attribute("y", "14");
        group2_text4
            .add_text(display_subject_label.to_string())
            .context(anyhow!("unable to generate svg"))?;

        group2
            .add_child(group2_text4)
            .context(anyhow!("unable to generate svg"))?;

        let mut group2_text5 = XMLElement::new("text");
        group2_text5.add_attribute(
            "x",
            &format!("{}", issuer_width + subject_width + (badge_width / 2.0)),
        );
        group2_text5.add_attribute("y", "15");
        group2_text5.add_attribute("fill", "#010101");
        group2_text5.add_attribute("fill-opacity", ".3");
        group2_text5
            .add_text(display_badge_label.to_string())
            .context(anyhow!("unable to generate svg"))?;

        group2
            .add_child(group2_text5)
            .context(anyhow!("unable to generate svg"))?;

        let mut group2_text6 = XMLElement::new("text");
        group2_text6.add_attribute(
            "x",
            &format!("{}", issuer_width + subject_width + (badge_width / 2.0)),
        );
        group2_text6.add_attribute("y", "14");
        group2_text6
            .add_text(display_badge_label.to_string())
            .context(anyhow!("unable to generate svg"))?;

        group2
            .add_child(group2_text6)
            .context(anyhow!("unable to generate svg"))?;
        group2
    };
    svg.add_child(group_two)
        .context(anyhow!("unable to generate svg"))?;

    xml.set_root_element(svg);

    let mut xml_buffer: Vec<u8> = Vec::new();
    xml.generate(&mut xml_buffer)
        .context(anyhow!("unable to generate svg"))?;

    Ok(xml_buffer)
}

const CONTENT_TYPE: axum::http::HeaderName = axum::http::HeaderName::from_static("content-type");
const CACHE_CONTROL: axum::http::HeaderName = axum::http::HeaderName::from_static("cache-control");
const CDN_CACHE_CONTROL: axum::http::HeaderName =
    axum::http::HeaderName::from_static("cdn-cache-control");
const ETAG: axum::http::HeaderName = axum::http::HeaderName::from_static("etag");

async fn handle_render_award_svg(
    State(web_context): State<WebContext>,
    verify_request: Query<VerifyRequest>,
) -> Result<impl IntoResponse, BlueBadgeError> {
    let uri = verify_request.uri.clone();

    if uri.is_none() {
        return Ok((StatusCode::NOT_FOUND).into_response());
    }

    let uri = uri.unwrap();

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(CONTENT_TYPE, "image/svg+xml".parse().unwrap());

    let verified_badge = verify_badge(web_context.http_client.clone(), &uri).await;

    if let Err(err) = verified_badge {
        tracing::error!("error verifying badge: {:?}", err);

        headers.insert(CACHE_CONTROL, "max-age=600".parse().unwrap());
        headers.insert(CDN_CACHE_CONTROL, "max-age=3600".parse().unwrap());

        let badge_svg = render_error_svg(
            &web_context.font,
            &format!("Error! Cannot Validate Record: {}", err),
        )?;
        return Ok((headers, badge_svg).into_response());
    }

    let verified_badge = verified_badge.unwrap();

    headers.insert(CACHE_CONTROL, "max-age=2160".parse().unwrap());
    headers.insert(CDN_CACHE_CONTROL, "max-age=8640".parse().unwrap());
    headers.insert(ETAG, verified_badge.cid.parse().unwrap());

    let issue_handle = verified_badge
        .issuer_handle
        .clone()
        .replace("https://", "@");
    let subject_handle = verified_badge
        .subject_handle
        .clone()
        .replace("https://", "@");

    let badge_svg = render_award_svg(
        &web_context.font,
        &issue_handle,
        &subject_handle,
        &verified_badge.badge_display_text,
    )?;

    Ok((headers, badge_svg).into_response())
}

async fn handle_render_award_png(
    State(web_context): State<WebContext>,
    verify_request: Query<VerifyRequest>,
) -> Result<impl IntoResponse, BlueBadgeError> {
    let uri = verify_request.uri.clone();

    if uri.is_none() {
        return Ok((StatusCode::NOT_FOUND).into_response());
    }

    let uri = uri.unwrap();

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(CONTENT_TYPE, "image/png".parse().unwrap());

    let verified_badge = verify_badge(web_context.http_client.clone(), &uri).await;

    let rendered_svg = match verified_badge {
        Err(err) => {
            tracing::error!("error verifying badge: {:?}", err);

            headers.insert(CACHE_CONTROL, "max-age=600".parse().unwrap());
            headers.insert(CDN_CACHE_CONTROL, "max-age=3600".parse().unwrap());

            render_error_svg(
                &web_context.font,
                &format!("Error! Cannot Validate Record: {}", err),
            )?
        }

        Ok(verified_badge) => {
            headers.insert(CACHE_CONTROL, "max-age=2160".parse().unwrap());
            headers.insert(CDN_CACHE_CONTROL, "max-age=8640".parse().unwrap());
            headers.insert(ETAG, verified_badge.cid.parse().unwrap());

            let issue_handle = verified_badge
                .issuer_handle
                .clone()
                .replace("https://", "@");
            let subject_handle = verified_badge
                .subject_handle
                .clone()
                .replace("https://", "@");

            render_award_svg(
                &web_context.font,
                &issue_handle,
                &subject_handle,
                &verified_badge.badge_display_text,
            )?
        }
    };

    let opt = usvg::Options {
        fontdb: web_context.fontdb.clone(),
        ..Default::default()
    };

    let tree = usvg::Tree::from_data(&rendered_svg, &opt)
        .context(anyhow!("unable to process rendered svg"))?;

    let pixmap_size = tree.size().to_int_size();
    let mut pixmap = tiny_skia::Pixmap::new(pixmap_size.width(), pixmap_size.height()).unwrap();
    resvg::render(&tree, tiny_skia::Transform::default(), &mut pixmap.as_mut());

    let badge_png = pixmap
        .encode_png()
        .context(anyhow!("unable to encode png"))?;

    Ok((headers, badge_png).into_response())
}

#[derive(Deserialize, Clone)]
pub struct LanguageForm {
    pub language: String,
}

const COOKIE_LANG: &str = "lang";

async fn handle_set_language(
    State(web_context): State<WebContext>,
    jar: CookieJar,
    Form(language_form): Form<LanguageForm>,
) -> Result<impl IntoResponse, BlueBadgeError> {
    let use_language = LanguageIdentifier::from_str(&language_form.language)
        .context(anyhow!("invalid language"))?;

    let found = web_context
        .supported_languages
        .iter()
        .find(|lang| lang.matches(&use_language, true, false));
    if found.is_none() {
        return Err(anyhow!("invalid language").into());
    }
    let found = found.unwrap();

    let mut cookie = Cookie::new(COOKIE_LANG, found.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(Some(SameSite::Lax));

    let updated_jar = jar.add(cookie);

    Ok((updated_jar, Redirect::to("/")).into_response())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    let http_external = env::var("HTTP_EXTERNAL").unwrap_or("https://badge.blue".to_string());

    let port: u32 = env::var("PORT")
        .context(anyhow!("PORT must be set"))
        .and_then(|port_value: String| port_value.parse::<u32>().context("invalid PORT value"))?;
    let listen = format!("0.0.0.0:{}", port);

    #[cfg(feature = "embed")]
    let jinja = embed_env::build_env(http_external.clone());

    #[cfg(feature = "reload")]
    let jinja = reload_env::build_env(&http_external);

    let font =
        ttf_parser::Face::parse(FONT_DATA, 0).context(anyhow!("unable to parse font data"))?;

    let mut font_database = fontdb::Database::new();
    font_database.load_font_data(FONT_DATA.to_vec());

    let supported_languages = vec![
        LanguageIdentifier::from_str("en")?,
        LanguageIdentifier::from_str("pt_BR")?,
    ];

    let web_context = WebContext(Arc::new(InnerWebContext {
        engine: Engine::from(jinja),
        http_client: reqwest::Client::new(),
        font,
        fontdb: Arc::new(font_database),
        supported_languages,
    }));

    let serve_dir = ServeDir::new("static");

    let app = Router::new()
        .nest_service("/static", serve_dir.clone())
        .fallback_service(serve_dir)
        .route("/", get(handle_index))
        .route("/language", post(handle_set_language))
        .route("/verify", get(handle_verify))
        .route("/render/badge", get(handle_render_award_png))
        .route("/render/badge.svg", get(handle_render_award_svg))
        .route("/render/badge.png", get(handle_render_award_png))
        .layer((
            TraceLayer::new_for_http(),
            TimeoutLayer::new(Duration::from_secs(30)),
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(http_external.parse::<HeaderValue>().unwrap())
                .allow_methods([Method::GET]),
        )
        .with_state(web_context.clone());

    let listener = TcpListener::bind(&listen).await.unwrap();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context(anyhow!("server error"))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
