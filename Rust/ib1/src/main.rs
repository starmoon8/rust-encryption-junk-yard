use axum::{
    response::{Html, Redirect},
    routing::get,
    Router,
    extract::{Path, Query},
};
use axum_extra::extract::Multipart;
use chrono::Utc;
use image::{imageops::FilterType, ImageFormat};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use regex::Regex;
use sqlx::{PgPool, Executor};
use std::env;
use dotenvy::dotenv;
use url::Url;
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
struct Post {
    id: i64,
    thread_id: i64,
    bump_timestamp: i64,
    name: String,
    subject: Option<String>,
    message: Option<String>,
    filename: Option<String>,
    thumbname: Option<String>,
    time: String,
}
type SharedState = Arc<PgPool>;
#[tokio::main]
async fn main() {
    dotenv().ok();
    let dev_mode = env::var("DEV_MODE").unwrap_or_default() == "true";
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    if dev_mode {
        reset_database(&database_url).await;
    }
    let pool = PgPool::connect(&database_url).await.expect("Failed to connect to Postgres");
    if dev_mode {
        seed_database(&pool).await;
    }
    let state = Arc::new(pool);
    let app = Router::new()
        .route("/", get(index).post(create_post))
        .route("/thread/:thread_id", get(get_thread).post(reply_post))
        .nest_service("/static", ServeDir::new("static"))
        .nest_service("/uploads", ServeDir::new("static/uploads"))
        .nest_service("/thumbs", ServeDir::new("static/thumbs"))
        .with_state(state);
    println!("ChessBoard live at http://localhost:3000");
    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
async fn reset_database(database_url: &str) {
    let url = Url::parse(database_url).expect("Invalid DATABASE_URL");
    let db_name = url.path().trim_start_matches('/').to_string();
    let mut default_url = url.clone();
    default_url.set_path("/postgres");
    let default_pool = PgPool::connect(default_url.as_str()).await.expect("Failed to connect to default Postgres DB");
    let _ = default_pool.execute(format!("DROP DATABASE IF EXISTS {};", db_name).as_str()).await;
    let _ = default_pool.execute(format!("CREATE DATABASE {};", db_name).as_str()).await;
    let pool = PgPool::connect(database_url).await.expect("Failed to connect to new DB");
    sqlx::migrate!().run(&pool).await.expect("Failed to run migrations");
}
async fn seed_database(pool: &PgPool) {
    let welcome = Post {
        id: 0, // placeholder
        thread_id: 1,
        bump_timestamp: Utc::now().timestamp(),
        name: "Anonymous".to_string(),
        subject: Some("Welcome to /chess/".to_string()),
        message: Some("First post! Let's discuss chess.\n>>greentext works".to_string()),
        filename: None,
        thumbname: None,
        time: Utc::now().format("%Y-%m-%d %H:%M").to_string(),
    };
    let id = sqlx::query!(
        r#"
        INSERT INTO posts (thread_id, bump_timestamp, name, subject, message, filename, thumbname, time)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
        welcome.thread_id as i64,
        welcome.bump_timestamp as i64,
        welcome.name,
        welcome.subject,
        welcome.message,
        welcome.filename,
        welcome.thumbname,
        welcome.time
    )
    .fetch_one(pool)
    .await
    .unwrap()
    .id;
    sqlx::query!(
        r#"
        UPDATE posts
        SET thread_id = $1
        WHERE id = $2
        "#,
        id as i64,
        id as i64
    )
    .execute(pool)
    .await
    .unwrap();
}
async fn index(
    Query(query): Query<HashMap<String, String>>,
    state: axum::extract::State<SharedState>,
) -> Html<String> {
    let page_str = query.get("page").cloned().unwrap_or_else(|| "1".to_string());
    let page: u64 = page_str.parse().unwrap_or(1).max(1);
    const PER_PAGE: i64 = 15;
    let total_threads: i64 = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) FROM posts WHERE id = thread_id
        "#
    )
    .fetch_one(&**state)
    .await
    .unwrap()
    .unwrap_or(0);
    let total_pages = if total_threads == 0 { 1 } else { ((total_threads as f64 / PER_PAGE as f64).ceil()) as u64 };
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * PER_PAGE;
    let ops: Vec<Post> = sqlx::query_as!(
        Post,
        r#"
        SELECT id, thread_id, bump_timestamp, name, subject, message, filename, thumbname, time
        FROM posts
        WHERE id = thread_id
        ORDER BY bump_timestamp DESC
        LIMIT $1 OFFSET $2
        "#,
        PER_PAGE,
        offset
    )
    .fetch_all(&**state)
    .await
    .unwrap();
    let mut threads: HashMap<i64, Vec<Post>> = HashMap::new();
    for op in &ops {
        let thread_posts: Vec<Post> = sqlx::query_as!(
            Post,
            r#"
            SELECT id, thread_id, bump_timestamp, name, subject, message, filename, thumbname, time
            FROM posts
            WHERE thread_id = $1
            ORDER BY id
            "#,
            op.thread_id
        )
        .fetch_all(&**state)
        .await
        .unwrap();
        threads.insert(op.thread_id, thread_posts);
    }
    let mut html = base_header("/", false);
    if let Some(error) = query.get("error") {
        html.push_str(&format!("<div class=\"banner\" style=\"background-color: #E04000; color: white;\">Error: {} <a href=\"/\" style=\"color: white;\">Try again</a></div><hr>", escape(error)));
    }
    for op in ops {
        let thread_posts = threads.get(&op.thread_id).unwrap().clone();
        html.push_str("<div class=\"thread\">");
        let replies = &thread_posts[1..];
        render_post(&mut html, &thread_posts[0], true, Some(replies.len()));
        let displayed_replies: &[Post];
        if replies.len() > 3 {
            displayed_replies = &replies[replies.len() - 3..];
        } else {
            displayed_replies = replies;
        }
        for reply in displayed_replies {
            render_post(&mut html, reply, false, None);
            html.push_str("<br>");
        }
        html.push_str("</div><hr>");
    }
    html.push_str(&render_pagination(page, total_pages));
    html.push_str("</body></html>");
    Html(html)
}
async fn get_thread(
    Query(query): Query<HashMap<String, String>>,
    state: axum::extract::State<SharedState>,
    Path(thread_id): Path<i64>,
) -> Html<String> {
    let thread_posts: Vec<Post> = sqlx::query_as!(
        Post,
        r#"
        SELECT id, thread_id, bump_timestamp, name, subject, message, filename, thumbname, time
        FROM posts
        WHERE thread_id = $1
        ORDER BY id
        "#,
        thread_id
    )
    .fetch_all(&**state)
    .await
    .unwrap();
    if thread_posts.is_empty() || thread_posts[0].id != thread_id {
        let html = "<html><body>Thread not found. <a href=\"/\">Return to board</a></body></html>".to_string();
        return Html(html);
    }
    let action = format!("/thread/{}", thread_id);
    let mut html = base_header(&action, true);
    if let Some(error) = query.get("error") {
        html.push_str(&format!("<div class=\"banner\" style=\"background-color: #E04000; color: white;\">Error: {} <a href=\"/thread/{}\" style=\"color: white;\">Try again</a></div><hr>", escape(error), thread_id));
    }
    html.push_str("<div class=\"thread\">");
    render_post(&mut html, &thread_posts[0], true, Some(thread_posts.len() - 1));
    for post in &thread_posts[1..] {
        render_post(&mut html, post, false, None);
        html.push_str("<br>");
    }
    html.push_str("</div><hr></body></html>");
    Html(html)
}
async fn create_post(
    state: axum::extract::State<SharedState>,
    mut multipart: Multipart,
) -> Redirect {
    let mut name = "Anonymous".to_string();
    let mut subject: Option<String> = None;
    let mut message: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut thumbname: Option<String> = None;
    let mut invalid_file = false;
    while let Some(field) = multipart.next_field().await.unwrap() {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "name" => {
                let text = field.text().await.unwrap_or_default().trim().to_string();
                if !text.is_empty() {
                    name = text;
                }
            }
            "subject" => {
                let text = field.text().await.unwrap_or_default();
                let trimmed = text.trim().to_string();
                if !trimmed.is_empty() {
                    subject = Some(trimmed);
                }
            }
            "message" => {
                let text = field.text().await.unwrap_or_default();
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    message = Some(text);
                }
            }
            "file" => {
                if let Some(original_name) = field.file_name() {
                    if original_name.is_empty() {
                        continue;
                    }
                    let ext = std::path::Path::new(original_name)
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let allowed_exts = vec!["jpg", "jpeg", "png", "gif", "webp"];
                    if !allowed_exts.contains(&ext.as_str()) {
                        let _ = field.bytes().await.unwrap_or_default(); // consume bytes
                        invalid_file = true;
                        continue;
                    }
                    let uuid = Uuid::new_v4().to_string();
                    let new_name = format!("{}.{}", uuid, ext);
                    let thumb_name = format!("{}_thumb.jpg", uuid);
                    let bytes = field.bytes().await.unwrap();
                    if bytes.is_empty() {
                        continue;
                    }
                    let upload_path = format!("static/uploads/{}", new_name);
                    let thumb_path = format!("static/thumbs/{}", thumb_name);
                    std::fs::write(&upload_path, &bytes).unwrap();
                    if let Ok(img) = image::load_from_memory(&bytes) {
                        let thumb = img.resize(150, 150, FilterType::Lanczos3);
                        thumb.save_with_format(&thumb_path, ImageFormat::Jpeg).unwrap();
                        thumbname = Some(thumb_name);
                    } else {
                        thumbname = None;
                    }
                    filename = Some(new_name);
                }
            }
            _ => {}
        }
    }
    if invalid_file {
        return Redirect::to("/?error=Invalid%20file%20type.%20Allowed:%20jpg,%20jpeg,%20png,%20gif,%20webp");
    }
    // Enforce required fields: subject and message must be present and non-empty
    if subject.is_none() || message.is_none() {
        return Redirect::to("/?error=Missing%20subject%20or%20comment");
    }
    let time = Utc::now().format("%Y-%m-%d %H:%M").to_string();
    let bump_timestamp = Utc::now().timestamp();
    let id = sqlx::query!(
        r#"
        INSERT INTO posts (thread_id, bump_timestamp, name, subject, message, filename, thumbname, time)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
        bump_timestamp as i64, // temp thread_id
        bump_timestamp as i64,
        name,
        subject,
        message,
        filename,
        thumbname,
        time
    )
    .fetch_one(&**state)
    .await
    .unwrap()
    .id;
    sqlx::query!(
        r#"
        UPDATE posts
        SET thread_id = $1
        WHERE id = $2
        "#,
        id as i64,
        id as i64
    )
    .execute(&**state)
    .await
    .unwrap();
    Redirect::to("/")
}
async fn reply_post(
    state: axum::extract::State<SharedState>,
    Path(thread_id): Path<i64>,
    mut multipart: Multipart,
) -> Redirect {
    let mut name = "Anonymous".to_string();
    let mut message: Option<String> = None;
    while let Some(field) = multipart.next_field().await.unwrap() {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "name" => {
                let text = field.text().await.unwrap_or_default().trim().to_string();
                if !text.is_empty() {
                    name = text;
                }
            }
            "message" => {
                let text = field.text().await.unwrap_or_default();
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    message = Some(text);
                }
            }
            _ => {}
        }
    }
    // Enforce required fields: only message must be non-empty
    if message.is_none() {
        return Redirect::to(&format!("/thread/{}?error=Missing%20comment", thread_id));
    }
    let time = Utc::now().format("%Y-%m-%d %H:%M").to_string();
    sqlx::query!(
        r#"
        INSERT INTO posts (thread_id, bump_timestamp, name, subject, message, filename, thumbname, time)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        thread_id as i64,
        0i64,
        name,
        None::<String>,
        message,
        None::<String>,
        None::<String>,
        time
    )
    .execute(&**state)
    .await
    .unwrap();
    sqlx::query!(
        r#"
        UPDATE posts
        SET bump_timestamp = $1
        WHERE id = $2
        "#,
        Utc::now().timestamp() as i64,
        thread_id as i64
    )
    .execute(&**state)
    .await
    .unwrap();
    Redirect::to(&format!("/thread/{}", thread_id))
}
fn base_header(action: &str, is_reply: bool) -> String {
    let mut header = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>/chess/ - Chess</title>
    <link rel="stylesheet" href="/static/default.css">
</head>
<body>
<header>
    <h1>/chess/ - Chess</h1>
    <div class="subtitle">General chess discussion, puzzles, and diagrams</div>
</header>
<hr>"#
    );
    if is_reply {
        header.push_str(r#"<div class="banner">Reply mode <a href="/">Return to the main board</a></div>"#);
    }
    header.push_str(&format!(
        r#"<form method="post" action="{}" enctype="multipart/form-data">
<table class="post-table">
<tbody>
    <tr><th>Name</th><td><input type="text" name="name" size="25" maxlength="35" autocomplete="off" placeholder="Anonymous"></td></tr>
"#,
        action
    ));
    if !is_reply {
        header.push_str(r#"<tr><th>Subject</th><td><input type="text" name="subject" size="25" maxlength="100" autocomplete="off"></td></tr>"#);
    }
    header.push_str(r#"<tr><th>Comment</th><td><textarea name="message" rows="5" cols="35"></textarea></td></tr>"#);
    if !is_reply {
        header.push_str(r#"<tr><th>File</th><td><input type="file" name="file" id="upload_file"></td></tr>"#);
    }
    header.push_str(r#"<tr><th></th><td><input accesskey="s" type="submit" name="post" value="Post" /></td></tr>
</tbody>
</table>
</form>
<hr>"#);
    header
}
fn render_post(html: &mut String, post: &Post, is_op: bool, reply_count: Option<usize>) {
    html.push_str(&format!("<div id=\"{}\" class=\"post {}\">", post.id, if is_op { "op" } else { "reply" }));
    html.push_str("<div class=\"intro\">");
    if let (Some(file), Some(thumb)) = (&post.filename, &post.thumbname) {
        if !file.is_empty() && !thumb.is_empty() {
            html.push_str(&format!(
                r#"<span class="file">
    <a href="/uploads/{}" target="_blank">
        <img src="/thumbs/{}" class="post-image">
    </a>
</span>"#,
                file, thumb
            ));
        }
    }
    if let Some(sub) = &post.subject {
        if !sub.is_empty() {
            html.push_str(&format!("<span class=\"subject\">{}</span> ", escape(sub)));
        }
    }
    let display_name = if post.name.is_empty() { "Anonymous" } else { &post.name };
    html.push_str(&format!(
        "<span class=\"name\">{}</span>",
        escape(display_name)
    ));
    if is_op {
        let count_str = if let Some(c) = reply_count { format!(" [{}]", c) } else { "".to_string() };
        html.push_str(&format!(" <a href=\"/thread/{}\">Reply{}</a>", post.thread_id, count_str));
    }
    html.push_str("</div><div class=\"body\">");
    if let Some(msg) = &post.message {
        if !msg.is_empty() {
            let quote_re = Regex::new(r"&gt;&gt;(\d+)").unwrap();
            let lines = msg.lines();
            for line in lines {
                let escaped = escape(line);
                let quoted = quote_re.replace_all(&escaped, |caps: &regex::Captures| {
                    format!(
                        "<a class=\"quotelink\" href=\"#{}\">&gt;&gt;{}</a>",
                        &caps[1], &caps[1]
                    )
                }).to_string();
                if line.starts_with('>') {
                    html.push_str("<span class=\"quote\">");
                    html.push_str(&quoted);
                    html.push_str("</span><br>");
                } else {
                    html.push_str(&quoted);
                    html.push_str("<br>");
                }
            }
        }
    }
    html.push_str("</div></div>");
}
fn render_pagination(page: u64, total_pages: u64) -> String {
    if total_pages <= 1 {
        return String::new();
    }
    let mut s = r#"<div class="pagination">"#.to_string();
    if page > 1 {
        s.push_str(&format!(r#"<a href="/?page={}">« Prev</a>"#, page - 1));
    }
    let start = if page > 3 { page - 2 } else { 1 };
    let end = if page + 2 > total_pages { total_pages } else { page + 2 };
    if start > 1 {
        s.push_str(r#"<a href="/?page=1">1</a>"#);
        if start > 2 {
            s.push_str("<span>...</span>");
        }
    }
    for p in start..=end {
        if p == page {
            s.push_str(&format!(r#"<span class="current">{}</span>"#, p));
        } else {
            s.push_str(&format!(r#"<a href="/?page={}">{}</a>"#, p, p));
        }
    }
    if end < total_pages {
        if end < total_pages - 1 {
            s.push_str("<span>...</span>");
        }
        s.push_str(&format!(r#"<a href="/?page={}">{}</a>"#, total_pages, total_pages));
    }
    if page < total_pages {
        s.push_str(&format!(r#"<a href="/?page={}">Next »</a>"#, page + 1));
    }
    s.push_str("</div>");
    s
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}