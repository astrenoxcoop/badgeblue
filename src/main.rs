use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{FromRef, Query, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
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
use std::{env, ops::Deref, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use axum_template::engine::Engine;

#[cfg(feature = "reload")]
use minijinja_autoreload::AutoReloader;

#[cfg(feature = "embed")]
use minijinja::Environment;

#[cfg(feature = "embed")]
pub(crate) type AppEngine = Engine<Environment<'static>>;

#[cfg(feature = "reload")]
pub(crate) type AppEngine = Engine<AutoReloader>;

// Make our own error that wraps `anyhow::Error`.
struct BlueBadgeError(anyhow::Error);

impl<E> From<E> for BlueBadgeError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for BlueBadgeError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

pub struct InnerWebContext {
    pub engine: AppEngine,
    pub http_client: reqwest::Client,
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

#[axum::debug_handler]
async fn handle_index(
    State(web_context): State<WebContext>,
) -> Result<impl IntoResponse, BlueBadgeError> {
    Ok(RenderHtml(
        "index.html",
        web_context.engine.clone(),
        template_context! {},
    )
    .into_response())
}

pub type QueryParam<'a> = (&'a str, &'a str);
pub type QueryParams<'a> = Vec<QueryParam<'a>>;

// TODO: urlencode
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
    good_prefixes: Vec<String>,
) -> Result<p256::PublicKey> {
    let (destination, key_id) = jwk_url
        .split_once("#")
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

pub fn verify_badge(key_id: &str, public_key: &p256::PublicKey, badge: &Award) -> Result<()> {
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

#[axum::debug_handler]
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

    let uri_parts = split_at_uri(&uri);
    if let Err(err) = uri_parts {
        tracing::error!("error split_at_uri: {:?}", err);
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Invalid URI provided.")],
            },
        )
        .into_response());
    }
    let [did, collection, rkey] = uri_parts.unwrap();

    let pds = pds_for_did(web_context.http_client.clone(), did).await;
    if let Err(err) = pds {
        tracing::error!("error pds_for_did: {:?}", err);
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Cannot resolve DID to PDS.")],
                uri,
            },
        )
        .into_response());
    }

    let (pds, _) = pds.unwrap();

    let record = get_record(web_context.http_client.clone(), &pds, did, collection, rkey).await;

    if let Err(err) = record {
        tracing::error!("error get_record: {:?}", err);
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Unable to get record from PDS.")],
                uri, did, collection, rkey, pds,
            },
        )
        .into_response());
    }

    let record = record.unwrap();

    let RecordType::Award(AwardWrapper::Award(award)) = record.value.clone();

    if award.proof.is_none() {
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Record has no proof.")],
                uri, did, collection, rkey, pds, record,
            },
        )
        .into_response());
    }

    let badge_uri_parts = split_at_uri(&award.badge.uri);
    if let Err(err) = badge_uri_parts {
        tracing::error!("error split_at_uri for badge: {:?}", err);
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Invalid badge.")],
            },
        )
        .into_response());
    }
    let [badge_did, badge_collection, _] = badge_uri_parts.unwrap();

    if validate_did(badge_did).is_err() {
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Invalid badge DID.")],
                uri, did, collection, rkey, pds, award,
            },
        )
        .into_response());
    }

    if badge_collection != "blue.badge.definition" {
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Invalid badge collection.")],
                uri, did, collection, rkey, pds, award,
            },
        )
        .into_response());
    }

    let badge_pds = pds_for_did(web_context.http_client.clone(), &badge_did).await;
    if let Err(err) = badge_pds {
        tracing::error!("error pds_for_did: {:?}", err);
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Cannot resolve badge DID to PDS.")],
                uri,
            },
        )
        .into_response());
    }

    let (_, badge_good_prefixes) = badge_pds.unwrap();

    let public_key = public_key_for_jwk_uri(
        web_context.http_client.clone(),
        &award.proof.clone().unwrap().key,
        badge_good_prefixes,
    )
    .await;

    if let Err(err) = public_key {
        tracing::error!("error public_key_for_jwk_uri: {:?}", err);
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Unable to get the public key from the JWK URI.")],
                uri, did, collection, rkey, pds, award,
            },
        )
        .into_response());
    }

    let public_key = public_key.unwrap();

    let verify = verify_badge(&award.proof.clone().unwrap().key, &public_key, &award);

    if let Err(err) = verify {
        tracing::error!("error public_key_for_jwk_uri: {:?}", err);
        return Ok(RenderHtml(
            "verify.html",
            web_context.engine.clone(),
            template_context! {
                messages => vec![Message::danger(None, "Signature verification failed.")],
                uri, did, collection, rkey, pds, award,
            },
        )
        .into_response());
    }

    Ok(RenderHtml(
        "verify.html",
        web_context.engine.clone(),
        template_context! {
            messages => vec![Message::success(None, "Record is valid!")],
            uri, did, collection, rkey, pds, award, record
        },
    )
    .into_response())
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

    let web_context = WebContext(Arc::new(InnerWebContext {
        engine: Engine::from(jinja),
        http_client: reqwest::Client::new(),
    }));

    let serve_dir = ServeDir::new("static");

    let app = Router::new()
        .nest_service("/static", serve_dir.clone())
        .fallback_service(serve_dir)
        .route("/", get(handle_index))
        .route("/verify", get(handle_verify))
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
