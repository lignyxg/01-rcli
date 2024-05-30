use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}
pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on port {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    //axum router
    let router = Router::new()
        .route("/*path", get(file_handler))
        .nest_service("/tower", ServeDir::new(path))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);
    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            Html(format!("File {} not found", p.display())),
        )
    } else if p.is_dir() {
        match tokio::fs::read_dir(p).await {
            Ok(mut entries) => {
                let mut content = String::new();
                while let Some(entry) = entries.next_entry().await.unwrap() {
                    content.push_str(
                        format!(
                            "<li><a href=\"{:?}\">{:?}</li>",
                            entry.path(),
                            entry.file_name()
                        )
                        .as_str(),
                    );
                }
                let content = format!("<html><body><ul>{}</ul></body></html>", content);
                (StatusCode::OK, Html(content))
            }
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Html(e.to_string())),
        }
    } else {
        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (StatusCode::OK, Html(content))
            }
            Err(e) => {
                warn!("Error reading file:{:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Html(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let response = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        let response = response.into_response();
        let status = response.status();
        assert_eq!(status, StatusCode::OK);
        let mut body = response.into_body().into_data_stream();
        let mut content = String::new();
        while let Some(Ok(bytes)) = body.next().await {
            content.push_str(std::str::from_utf8(bytes.as_ref()).unwrap());
        }
        assert!(content.trim().starts_with("[package]"));
    }
}
