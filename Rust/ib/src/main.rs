use axum::{
    extract::Multipart,
    response::{Html, Redirect},
    routing::{get, post},
    Router,
};
use html_escape::encode_safe;
use std::path::Path;
use tokio::fs::{create_dir_all, read_to_string, write};
use tower_http::services::ServeDir;

async fn serve_index() -> Html<String> {
    match read_to_string("index.html").await {
        Ok(content) => Html(content),
        Err(_) => Html("<h1>Error loading page</h1>".to_string()),
    }
}

async fn handle_post(mut multipart: Multipart) -> Result<Redirect, Html<String>> {
    let mut name = "Anonymous".to_string();
    let mut subject = String::new();
    let mut message = String::new();
    let mut file_url: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| Html(format!("<h1>Error: {}</h1>", e)))? {
        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "name" {
            name = field.text().await.map_err(|e| Html(format!("<h1>Error: {}</h1>", e)))?.trim().to_string();
            if name.is_empty() {
                name = "Anonymous".to_string();
            }
        } else if field_name == "subject" {
            subject = field.text().await.map_err(|e| Html(format!("<h1>Error: {}</h1>", e)))?;
        } else if field_name == "message" {
            message = field.text().await.map_err(|e| Html(format!("<h1>Error: {}</h1>", e)))?;
        } else if field_name == "file" {
            if let Some(filename) = field.file_name() {
                let filename = filename.to_string();
                if !filename.is_empty() {
                    let data = field.bytes().await.map_err(|e| Html(format!("<h1>Error: {}</h1>", e)))?;
                    let uploads_dir = Path::new("static/uploads");
                    if !uploads_dir.exists() {
                        create_dir_all(uploads_dir).await.map_err(|e| Html(format!("<h1>Error creating dir: {}</h1>", e)))?;
                    }
                    let path = uploads_dir.join(&filename);
                    write(&path, &data).await.map_err(|e| Html(format!("<h1>Error writing file: {}</h1>", e)))?;
                    file_url = Some(format!("/static/uploads/{}", filename));
                }
            }
        }
    }

    if message.trim().is_empty() {
        return Err(Html("<h1><a href=\"/\">Message empty - Click here to return</a></h1>".to_string()));
    }

    let escaped_name = encode_safe(&name).to_string();
    let escaped_subject = encode_safe(&subject).to_string();
    let escaped_message = encode_safe(&message).to_string().replace("\n", "<br>");  // Preserve line breaks

    let mut snippet = format!(
        "<table class=\"post-table\"><tr><td class=\"post\"><div class=\"name\"><b>{}</b></div><div class=\"subject\"><b>{}</b></div>",
        escaped_name, escaped_subject
    );

    if let Some(url) = file_url {
        snippet.push_str(&format!("<img src=\"{}\" alt=\"Uploaded image\" /><br>", url));
    }

    snippet.push_str(&format!(
        "<div class=\"message\">{}</div></td></tr></table><hr>",
        escaped_message
    ));

    // Read current index.html
    let mut content = read_to_string("index.html").await.map_err(|e| Html(format!("<h1>Error reading file: {}</h1>", e)))?;

    // Insert snippet before the last <hr> before </body> to add below form but above previous posts
    if let Some(pos) = content.rfind("<hr></body>") {
        content.insert_str(pos, &snippet);
    } else if let Some(pos) = content.rfind("</body>") {
        content.insert_str(pos, &snippet);
    } else {
        return Err(Html("<h1>Error: Invalid HTML structure</h1>".to_string()));
    }

    // Write back
    write("index.html", content).await.map_err(|e| Html(format!("<h1>Error writing file: {}</h1>", e)))?;

    Ok(Redirect::to("/"))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/post", post(handle_post))
        .nest_service("/static", ServeDir::new("static"));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}