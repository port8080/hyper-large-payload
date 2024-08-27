use std::fs::{File, read};
use std::io::BufRead;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::{Request, Response};
use rand::Rng;
use rustls_pemfile::{Item, read_one_from_slice};
use rustls_pki_types::CertificateDer;
use crate::{FRAME_SIZE, LARGE_PAYLOAD_SIZE, SERVER_CONF_FILE};

pub(crate) fn try_from_pem(pem: &[u8]) -> anyhow::Result<CertificateDer> {
    let (item, _) = read_one_from_slice(pem)
        .map_err(|e| {
            anyhow!("rustls_pemfile error {e:?}")
        })?
        .ok_or_else(|| anyhow!("failed to parse pem"))?;
    match item {
        Item::X509Certificate(cert) => Ok(cert),
        _ => Err(anyhow!("invalid cert format")),
    }
}
pub(crate) fn get_file_bytes(input_file: &str) -> Vec<u8> {
    read(input_file).unwrap_or_else(|_| panic!("Failed to read {input_file}"))
}
fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn generate_random_bytes(size: usize) -> Bytes {
    let mut rng = rand::thread_rng();
    Bytes::from((0..size).map(|_| rng.random::<u8>()).collect::<Vec<u8>>())
}

pub(crate) fn full() -> BoxBody<Bytes, hyper::Error> {
    Full::new(generate_random_bytes(LARGE_PAYLOAD_SIZE))
        .map_err(|never| match never {})
        .boxed()
}

fn generate_random_bytes_frames(size: usize, chunk_size: usize) -> Vec<anyhow::Result<hyper::body::Frame<hyper::body::Bytes>, std::convert::Infallible>> {
    let mut frames = Vec::new();
    let mut rng = rand::thread_rng();
    let mut remaining_size = size;
    while remaining_size > 0 {
        let current_chunk_size = remaining_size.min(chunk_size);
        let chunk: Vec<u8> = (0..current_chunk_size).map(|_| rng.random::<u8>()).collect();
        frames.push(Ok(hyper::body::Frame::data(hyper::body::Bytes::from(chunk))));
        remaining_size -= current_chunk_size;
    }
    frames
}

pub(crate) fn full_framed() -> BoxBody<Bytes, hyper::Error> {
    let frames = generate_random_bytes_frames(LARGE_PAYLOAD_SIZE, FRAME_SIZE);
    let stream = futures_util::stream::iter(frames);
    StreamBody::new(stream).map_err(|never| match never {}).boxed()
}

pub(crate) async fn echo(
    _req: Request<hyper::body::Incoming>,
) -> anyhow::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::new(empty()))
}

pub(crate) fn extract_host() -> Result<Option<String>> {
    // Open the file in read-only mode
    let file = File::open(SERVER_CONF_FILE)?;
    let reader = std::io::BufReader::new(file);

    // Iterate through each line in the file
    for line in reader.lines() {
        let line = line?;
        // Check if the line contains "subjectAltName="
        if line.starts_with("subjectAltName=") {
            // Extract the value after "DNS:"
            if let Some(pos) = line.find("DNS:") {
                let hostname = line[pos + 4..].trim();
                return Ok(Some(hostname.to_string()));
            }
        }
    }

    // Return None if "localhost" wasn't found
    Ok(None)
}