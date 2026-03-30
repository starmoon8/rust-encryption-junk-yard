use axum::{
    extract::{Multipart, State},
    response::{Html, Redirect},
    routing::{get, post},
    Router,
};
use chrono::prelude::*;
use html_escape::encode_safe;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::{create_dir_all, read_to_string, write};
use tokio::sync::Mutex;
use tower_http::services::ServeDir;
use uuid::Uuid;
use shakmaty::{Board, Color, Role, Rank, File, Square, Chess, Position, CastlingMode, fen::Fen};

fn get_unicode(color: Color, role: Role) -> String {
    match (color, role) {
        (Color::White, Role::King) => "♔".to_string(),
        (Color::White, Role::Queen) => "♕".to_string(),
        (Color::White, Role::Rook) => "♖".to_string(),
        (Color::White, Role::Bishop) => "♗".to_string(),
        (Color::White, Role::Knight) => "♘".to_string(),
        (Color::White, Role::Pawn) => "♙".to_string(),
        (Color::Black, Role::King) => "♚".to_string(),
        (Color::Black, Role::Queen) => "♛".to_string(),
        (Color::Black, Role::Rook) => "♜".to_string(),
        (Color::Black, Role::Bishop) => "♝".to_string(),
        (Color::Black, Role::Knight) => "♞".to_string(),
        (Color::Black, Role::Pawn) => "♟".to_string(),
    }
}

fn fen_to_html(board: &Board) -> String {
    let mut html = "<table class=\"chess-board\"><tbody>".to_string();
    for r in (0..8).rev() {
        let rank = Rank::new(r as u32);
        html.push_str("<tr>");
        for f in 0..8 {
            let file = File::new(f as u32);
            let square = Square::from_coords(file, rank);
            let piece_str = board.piece_at(square).map_or("&nbsp;".to_string(), |piece| {
                get_unicode(piece.color, piece.role)
            });
            let sq_class = if (r + f) % 2 == 0 { "light" } else { "dark" };
            html.push_str(&format!("<td class=\"{}\">{}</td>", sq_class, piece_str));
        }
        html.push_str("</tr>");
    }
    html.push_str("</tbody></table>");
    html
}

async fn serve_index(State(mutex): State<Arc<Mutex<()>>>) -> Html<String> {
    let _guard = mutex.lock().await;
    match read_to_string("index.html").await {
        Ok(content) => Html(content),
        Err(_) => Html("<h1>Error loading page</h1>".to_string()),
    }
}

async fn handle_post(
    State(mutex): State<Arc<Mutex<()>>>,
    mut multipart: Multipart,
) -> Result<Redirect, Html<String>> {
    let mut name = "Anonymous".to_string();
    let mut subject = String::new();
    let mut message = String::new();
    let mut fen = String::new();
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
        } else if field_name == "fen" {
            fen = field.text().await.map_err(|e| Html(format!("<h1>Error: {}</h1>", e)))?;
        } else if field_name == "file" {
            if let Some(filename) = field.file_name() {
                let filename = filename.to_string();
                if !filename.is_empty() {
                    let content_type = field.content_type().unwrap_or("").to_string();
                    if content_type.starts_with("image/") {
                        let data = field.bytes().await.map_err(|e| Html(format!("<h1>Error: {}</h1>", e)))?;
                        if data.len() > 5 * 1024 * 1024 {
                            return Err(Html("<h1>File too large (max 5MB)</h1>".to_string()));
                        }
                        let ext = Path::new(&filename).extension().and_then(|os| os.to_str()).unwrap_or("");
                        if ext.is_empty() {
                            continue;
                        }
                        let uuid_str = Uuid::new_v4().simple().to_string();
                        let new_filename = format!("{}.{}", uuid_str, ext);
                        let uploads_dir = Path::new("static/uploads");
                        if !uploads_dir.exists() {
                            create_dir_all(uploads_dir).await.map_err(|e| Html(format!("<h1>Error creating dir: {}</h1>", e)))?;
                        }
                        let path = uploads_dir.join(&new_filename);
                        write(&path, &data).await.map_err(|e| Html(format!("<h1>Error writing file: {}</h1>", e)))?;
                        file_url = Some(format!("/static/uploads/{}", new_filename));
                    }
                }
            }
        }
    }

    if message.trim().is_empty() {
        return Err(Html("<h1><a href=\"/\">Message empty - Click here to return</a></h1>".to_string()));
    }

    let now = Utc::now();
    let formatted_date = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let escaped_date = encode_safe(&formatted_date).to_string();
    let escaped_name = encode_safe(&name).to_string();
    let escaped_subject = encode_safe(&subject).to_string();
    let escaped_message = encode_safe(&message).to_string().replace("\n", "<br>");

    let mut snippet = format!(
        "<hr><table class=\"post-table\"><tr><td class=\"post\"><div class=\"name\"><b>{}</b></div><div class=\"subject\"><b>{}</b></div><div class=\"date\">{}</div>",
        escaped_name, escaped_subject, escaped_date
    );
    if let Some(url) = file_url {
        snippet.push_str(&format!("<img src=\"{}\" alt=\"Uploaded image\" /><br>", url));
    }
    if !fen.trim().is_empty() {
        if let Ok(fen_obj) = Fen::from_ascii(fen.as_bytes()) {
            if let Ok(pos) = fen_obj.into_position::<Chess>(CastlingMode::Standard) {
                let board_html = fen_to_html(&pos.board());
                snippet.push_str(&format!("<div class=\"diagram\">{}</div><br>", board_html));
            }
        }
    }
    snippet.push_str(&format!(
        "<div class=\"message\">{}</div></td></tr></table>",
        escaped_message
    ));

    let _guard = mutex.lock().await;
    let mut content = read_to_string("index.html").await.map_err(|e| Html(format!("<h1>Error reading file: {}</h1>", e)))?;
    if let Some(pos) = content.rfind("</form>") {
        let insert_pos = pos + 7;
        content.insert_str(insert_pos, &snippet);
    } else {
        return Err(Html("<h1>Error: Invalid HTML structure</h1>".to_string()));
    }
    write("index.html", content).await.map_err(|e| Html(format!("<h1>Error writing file: {}</h1>", e)))?;

    Ok(Redirect::to("/"))
}

#[tokio::main]
async fn main() {
    let index_mutex = Arc::new(Mutex::new(()));

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/post", post(handle_post))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(index_mutex);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}