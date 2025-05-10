use std::cell::OnceCell;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use bytes::Bytes;
use clap::Parser;
use color_eyre::eyre::eyre;
use color_eyre::{eyre::Report, eyre::WrapErr, Result};
use containers_image_proxy::oci_spec;
use containers_image_proxy::oci_spec::image::{Descriptor, ImageManifest};
use futures_util::TryStreamExt as _;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use oci_spec::image::Digest;
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;
use tracing::{info, instrument, span, Instrument, Level};

static NOTFOUND: &[u8] = b"Not Found";
static METHOD_NOT_ALLOWED: &[u8] = b"Method Not Allowed";

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// TCP port
    #[clap(long, short = 'p', default_value_t = 8000)]
    port: u16,
}

/// HTTP status code 404
fn not_found() -> Response<BoxBody<Bytes, Report>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(NOTFOUND.into()).map_err(|e| match e {}).boxed())
        .unwrap()
}

fn method_not_allowed() -> Response<BoxBody<Bytes, Report>> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(
            Full::new(METHOD_NOT_ALLOWED.into())
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

fn v2_true() -> Response<BoxBody<Bytes, Report>> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new("true".into()).map_err(|e| match e {}).boxed())
        .unwrap()
}

fn internal_server_error(e: Report) -> Response<BoxBody<Bytes, Report>> {
    tracing::error!("{e:?}");
    let e = format!("Internal Server Error: {e}");
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(e.into()).map_err(|e| match e {}).boxed())
        .unwrap()
}

#[derive(Debug)]
struct OpenedState {
    repo: String,
    oi: containers_image_proxy::OpenedImage,
    raw_manifest: Vec<u8>,
}

#[derive(Debug)]
struct State {
    id: u64,
    proxy: containers_image_proxy::ImageProxy,
    opened_image: OnceCell<OpenedState>,
}

#[instrument]
#[tokio::main]
async fn main() -> Result<(), Report> {
    install_tracing();

    color_eyre::install()?;

    let args = Args::parse();
    // tokio listener loop on args.port
    let addr = format!("127.0.0.1:{}", args.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .wrap_err_with(|| format!("Failed to bind to {}", addr))?;

    info!("Listening on {}", addr);

    let stateid = AtomicU64::new(0);

    loop {
        let (stream, addr) = listener.accept().await?;
        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        let state = State {
            id: stateid.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            proxy: containers_image_proxy::ImageProxy::new().await?,
            opened_image: Default::default(),
        };
        let span = tracing::span!(
            Level::DEBUG,
            "client",
            addr = addr.to_string(),
            state = state.id
        );
        let state = Arc::new(Mutex::new(state));
        let service = service_fn(move |req| response(Arc::clone(&state), req));
        tokio::task::spawn(
            async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    tracing::info!("Error serving connection: {}", err);
                    return;
                } else {
                    tracing::debug!("Connection closed");
                }
            }
            .instrument(span),
        );
    }
}

fn install_tracing() {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let fmt_layer = fmt::layer().with_target(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default())
        .init();
}

fn response_for_raw_manifest(manifest: &[u8]) -> Response<BoxBody<Bytes, Report>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            oci_spec::image::MediaType::ImageManifest.to_string(),
        )
        .header(header::CONTENT_LENGTH, format!("{}", manifest.len()))
        .body(
            http_body_util::Full::new(Bytes::copy_from_slice(manifest))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

#[instrument(skip(state))]
async fn get_manifest(
    state: Arc<Mutex<State>>,
    reference: &str,
) -> Result<Response<BoxBody<Bytes, Report>>> {
    let reference = oci_spec::distribution::Reference::try_from(reference)?;
    let repo = format!("{}/{}", reference.registry(), reference.repository());
    let cstorage_reference = &format!("containers-storage:{reference}");
    let state = state.lock().await;
    if let Some(oi) = state.opened_image.get() {
        tracing::trace!("already have opened image");
        return Ok(response_for_raw_manifest(oi.raw_manifest.as_slice()));
    }
    tracing::debug!("opening");
    let oi = state.proxy.open_image_optional(&cstorage_reference).await?;
    let Some(oi) = oi else {
        return Ok(not_found());
    };
    let (_digest, raw_manifest) = state.proxy.fetch_manifest_raw_oci(&oi).await?;
    tracing::debug!("Fetched manifest ({} bytes)", raw_manifest.len());
    let mut manifest: ImageManifest =
        serde_json::from_slice(&raw_manifest).with_context(|| format!("Parsing manifest"))?;
    let layers_for_copy = state
        .proxy
        .get_layer_info(&oi)
        .await?
        .ok_or_else(|| eyre!("Expected layerinfo when operating on containers-storage:"))?;
    // Override with the uncompressed layers
    manifest.set_layers(
        layers_for_copy
            .into_iter()
            .map(|v| Descriptor::new(v.media_type, v.size, v.digest))
            .collect(),
    );
    let raw_manifest = serde_json::to_vec(&manifest).context("Serializing manifest")?;
    let ostate = OpenedState {
        repo: repo.to_string(),
        oi,
        raw_manifest,
    };
    let resp = response_for_raw_manifest(&ostate.raw_manifest);
    let _ = state.opened_image.set(ostate);
    Ok(resp)
}

#[instrument(skip(state))]
async fn get_blob(
    state: Arc<Mutex<State>>,
    repository: &str,
    blobid: &str,
) -> Result<Response<BoxBody<Bytes, Report>>> {
    let state = state.lock().await;
    let ostate = state
        .opened_image
        .get()
        .ok_or_else(|| eyre!("Must fetch manifest before body"))?;
    if ostate.repo != repository {
        tracing::debug!("Repository mismatch");
        return Err(eyre!(
            "Repository mismatch, expected={} provided={}",
            ostate.repo,
            repository
        ));
    }
    let oi = &ostate.oi;
    let digest = &Digest::from_str(blobid).context("Parsing digest")?;
    let _span = span!(Level::DEBUG, "Fetching blob");
    let (blobsize, fd) = state
        .proxy
        .get_raw_blob(oi, digest)
        .await
        .context("Invoking GetRawBlob")?;
    tracing::debug!("Fetched blob ({} bytes)", blobsize);
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_LENGTH, blobsize.to_string());
    let reader_stream = ReaderStream::new(fd).map_err(|e| eyre!(e));
    let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
    let boxed_body = stream_body.boxed();
    Ok(resp.body(boxed_body).unwrap())
}

async fn impl_response(
    proxy: Arc<Mutex<State>>,
    req: Request<hyper::body::Incoming>,
) -> Response<BoxBody<Bytes, Report>> {
    if !matches!(req.method(), &Method::GET) {
        return method_not_allowed();
    }
    let path = req.uri().path();
    let Some(path) = path.strip_prefix("/v2/") else {
        return not_found();
    };
    if path.is_empty() {
        return v2_true();
    }
    let Some((repository_and_method, key)) = path.rsplit_once('/') else {
        tracing::debug!("Invalid method: {path}");
        return not_found();
    };
    let Some((repository, method)) = repository_and_method.rsplit_once('/') else {
        tracing::debug!("Invalid method: {path}");
        return not_found();
    };
    tracing::debug!("repository={repository}, method={method}, key={key}");
    let r = match method {
        "manifests" => {
            let imgref = format!("{repository}:{key}");
            get_manifest(proxy, &imgref).await
        }
        "blobs" => get_blob(proxy, repository, key).await,
        _ => Ok(not_found()),
    };
    match r {
        Ok(r) => r,
        Err(e) => internal_server_error(e),
    }
}
async fn response(
    proxy: Arc<Mutex<State>>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, Report>>> {
    Ok(impl_response(proxy, req).await)
}
