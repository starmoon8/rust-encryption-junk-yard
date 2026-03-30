<?php
declare(strict_types=1);

// Configuration
const POSTS_PER_PAGE = 10;
const MAX_UPLOAD_SIZE = 30 * 1024 * 1024; // 30 MB
const MAX_PREVIEW_CHARS = 1000;
const MAIN_REPLIES_SHOWN = 0;
const MAX_REPLY_PREVIEW_CHARS = 1000;
const ALLOWED_FILE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/webm', 'video/mp4'];

session_start([
    'cookie_lifetime' => 86400,
    'cookie_httponly' => true,
    'cookie_secure' => true,
    'cookie_samesite' => 'Strict',
]);

// Regenerate session ID to prevent session fixation
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

try {
    $db = new SQLite3('message_board.db');
    $db->enableExceptions(true);
} catch (Exception $e) {
    die('Database connection failed: ' . $e->getMessage());
}

// Create posts table if it doesn't exist
$db->exec('CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    media TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)');

// Create replies table if it doesn't exist
$db->exec('CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    FOREIGN KEY(post_id) REFERENCES posts(id)
)');

// Create trigger to update timestamp on post update
$db->exec('CREATE TRIGGER IF NOT EXISTS update_timestamp
           AFTER UPDATE ON posts
           FOR EACH ROW
           WHEN NEW.updated_at <= OLD.updated_at
           BEGIN
               UPDATE posts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
           END');

$uploadsDir = 'uploads/';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0755, true);
}

function getUniqueFilename(string $directory, string $originalFilename): string {
    $extension = pathinfo($originalFilename, PATHINFO_EXTENSION);
    $basename = bin2hex(random_bytes(8)); // Random hex for security, ignore original name
    $newFilename = $basename . ($extension ? '.' . $extension : '');
    $counter = 1;

    while (file_exists($directory . $newFilename)) {
        $newFilename = $basename . '-' . $counter . ($extension ? '.' . $extension : '');
        $counter++;
    }

    return $newFilename;
}

function getReplyCount(SQLite3 $db, int $post_id): int {
    $stmt = $db->prepare('SELECT COUNT(*) as count FROM replies WHERE post_id = :post_id');
    $stmt->bindValue(':post_id', $post_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return (int)($row['count'] ?? 0);
}

function renderPost(int $id, string $title, string $message, ?string $mediaPath, bool $showReplyButton = true): string {
    global $db;
    $replyCount = $showReplyButton ? getReplyCount($db, $id) : 0;
    $mediaTag = '';
    if ($mediaPath) {
        $fileType = mime_content_type($mediaPath);
        if (str_starts_with($fileType, 'video/')) {
            $mediaTag = '<video class="post-media" controls width="200" height="200"><source src="' . htmlspecialchars($mediaPath) . '"></video>';
        } elseif (str_starts_with($fileType, 'image/')) {
            $mediaTag = '<img class="post-media" src="' . htmlspecialchars($mediaPath) . '" alt="media">';
        }
    }
    $replyLink = '';
    if ($showReplyButton) {
        $replyLink = '<a class="reply-button" href="index.php?post_id=' . $id . '">[reply-' . $replyCount . ']</a>';
    }
    $displayMessage = $message;
    $readMoreLink = '';
    if ($showReplyButton && strlen($message) > MAX_PREVIEW_CHARS) {
        $displayMessage = substr($message, 0, MAX_PREVIEW_CHARS);
        $readMoreLink = '<a class="read-more-button" href="index.php?post_id=' . $id . '">[more]</a>';
    }
    $repliesHtml = '';
    if ($showReplyButton && MAIN_REPLIES_SHOWN > 0 && $replyCount > 0) {
        $repliesHtml = '<div class="replies-preview">';
        $replyStmt = $db->prepare('SELECT * FROM replies WHERE post_id = :post_id ORDER BY id DESC LIMIT :limit');
        $replyStmt->bindValue(':post_id', $id, SQLITE3_INTEGER);
        $replyStmt->bindValue(':limit', MAIN_REPLIES_SHOWN, SQLITE3_INTEGER);
        $repliesResult = $replyStmt->execute();
        while ($reply = $repliesResult->fetchArray(SQLITE3_ASSOC)) {
            $replyMessage = $reply['message'];
            $replyMoreLink = '';
            if (strlen($replyMessage) > MAX_REPLY_PREVIEW_CHARS) {
                $replyMessage = substr($replyMessage, 0, MAX_REPLY_PREVIEW_CHARS);
                $replyMoreLink = '<a class="read-more-button" href="index.php?post_id=' . $id . '">[more]</a>';
            }
            $repliesHtml .= '<div class="reply"><p>' . nl2br(htmlspecialchars($replyMessage)) . $replyMoreLink . '</p></div>';
        }
        $repliesHtml .= '</div>';
    }
    return '
        <div class="post">
            <hr class="green-hr">
            <div class="post-media-container">' . $mediaTag . '</div>
            <h2>' . htmlspecialchars($title) . '</h2>
            <p style="word-wrap: break-word; overflow-wrap: break-word;">' . nl2br(htmlspecialchars($displayMessage)) . $readMoreLink . '</p>
            ' . $replyLink . $repliesHtml . '
        </div>
    ';
}

function renderReply(string $message): string {
    return '<div class="reply"><p>' . nl2br(htmlspecialchars($message)) . '</p></div>';
}

function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(string $token): bool {
    return hash_equals($token, $_SESSION['csrf_token'] ?? '');
}

$csrf_token = generateCsrfToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_token_post = $_POST['csrf_token'] ?? '';
    if (!validateCsrfToken($csrf_token_post)) {
        http_response_code(403);
        die('Invalid CSRF token');
    }

    $message = trim($_POST['message'] ?? '');
    if (strlen($message) === 0 || strlen($message) > 100000) {
        http_response_code(400);
        die('Message is required and must be between 1 and 100000 characters.');
    }

    if (isset($_POST['post_id'])) {
        // Handle new reply
        $post_id = filter_input(INPUT_POST, 'post_id', FILTER_VALIDATE_INT);
        if ($post_id === false || $post_id <= 0) {
            http_response_code(400);
            die('Invalid post ID.');
        }
        $stmt = $db->prepare('INSERT INTO replies (post_id, message) VALUES (:post_id, :message)');
        $stmt->bindValue(':post_id', $post_id, SQLITE3_INTEGER);
        $stmt->bindValue(':message', $message, SQLITE3_TEXT);
        $result = $stmt->execute();
        if ($result) {
            // Bump the original post (no-op to trigger update)
            $bumpStmt = $db->prepare('UPDATE posts SET id = id WHERE id = :post_id');
            $bumpStmt->bindValue(':post_id', $post_id, SQLITE3_INTEGER);
            $bumpStmt->execute();
        }
        header('Location: ' . $_SERVER['PHP_SELF'] . '?post_id=' . $post_id);
        exit;
    } else {
        // Handle new post
        $title = trim($_POST['title'] ?? '');
        if (strlen($title) === 0 || strlen($title) > 20) {
            http_response_code(400);
            die('Title is required and must be between 1 and 20 characters.');
        }
        $media = $_FILES['media'] ?? [];
        $mediaPath = null;
        if (isset($media['tmp_name']) && $media['size'] > 0) {
            $tmpName = $media['tmp_name'];
            if (!is_uploaded_file($tmpName)) {
                http_response_code(400);
                die('Invalid file upload.');
            }
            $fileType = mime_content_type($tmpName);
            if (!in_array($fileType, ALLOWED_FILE_TYPES, true)) {
                http_response_code(400);
                die('Invalid file type.');
            }
            if ($media['size'] > MAX_UPLOAD_SIZE) {
                http_response_code(400);
                die('File too large.');
            }
            $uniqueFilename = getUniqueFilename($uploadsDir, $media['name']);
            $mediaPath = $uploadsDir . $uniqueFilename;
            if (!move_uploaded_file($tmpName, $mediaPath)) {
                http_response_code(500);
                die('Failed to move uploaded file.');
            }
        }
        $stmt = $db->prepare('INSERT INTO posts (title, message, media) VALUES (:title, :message, :media)');
        $stmt->bindValue(':title', $title, SQLITE3_TEXT);
        $stmt->bindValue(':message', $message, SQLITE3_TEXT);
        $stmt->bindValue(':media', $mediaPath, SQLITE3_TEXT);
        $stmt->execute();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
}

// Pagination for main view
$totalPosts = (int)$db->querySingle('SELECT COUNT(*) FROM posts');
$totalPages = (int)ceil($totalPosts / POSTS_PER_PAGE);
$page = max(1, (int)filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT) ?: 1);
$offset = ($page - 1) * POSTS_PER_PAGE;
$post_id = filter_input(INPUT_GET, 'post_id', FILTER_VALIDATE_INT) ?: null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Message Board</title>
    <style>
        body {
            background-color: #B0C4DE;
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
        }
        .message-board {
            width: 90%;
            max-width: 1200px;
            margin: auto;
            padding: 20px;
            background: #F0F0F0;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        .form-container {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }
        .form-container form {
            width: 100%;
            max-width: 600px;
            display: none;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        .post {
            margin-bottom: 20px;
            padding: 10px;
            background: #E0E0E0;
            border-radius: 5px;
            position: relative;
        }
        .green-hr {
            border: 5px solid green;
        }
        .post-media {
            width: 200px;
            height: auto;
            cursor: pointer;
            object-fit: contain;
        }
        .post-media.expanded {
            width: 100%;
            max-width: 100%;
            height: auto;
        }
        .post-media video {
            width: 100%;
            height: auto;
        }
        form input[type="text"], form textarea, form input[type="file"], form input[type="text"], form button {
            width: 100%;
            margin-bottom: 10px;
        }
        form textarea {
            height: 100px;
        }
        form button {
            padding: 10px;
            background: green;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .toggle-buttons {
            text-align: center;
            margin-bottom: 20px;
        }
        .toggle-buttons button {
            padding: 10px;
            background: green;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .toggle-buttons .close-button {
            background: red;
            display: none;
        }
        .reply-button {
            position: absolute;
            top: 10px;
            right: 10px;
            background: blue;
            color: white;
            padding: 5px 10px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
        }
        .read-more-button {
            background: green;
            color: white;
            padding: 2px 5px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .replies-preview {
            margin-top: 10px;
            padding: 0;
            background: none;
        }
        .pagination {
            text-align: center;
            margin-top: 20px;
        }
        .pagination a {
            margin: 0 5px;
            padding: 10px 15px;
            background: #ddd;
            color: #000;
            text-decoration: none;
            border-radius: 5px;
        }
        .pagination a.active {
            background: #333;
            color: #fff;
        }
        .reply {
            margin-bottom: 10px;
            padding: 10px;
            background: #D0D0D0;
            border-radius: 5px;
            width: fit-content;
            max-width: min(100%, 75ch);
        }
        .reply p {
            word-wrap: break-word;
            overflow-wrap: break-word;
            margin: 0;
        }
        .back-link {
            display: block;
            margin-bottom: 20px;
            color: blue;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="message-board">
        <?php if ($post_id !== null && $post_id > 0): ?>
            <?php
            $stmt = $db->prepare('SELECT * FROM posts WHERE id = :id');
            $stmt->bindValue(':id', $post_id, SQLITE3_INTEGER);
            $result = $stmt->execute();
            $post = $result->fetchArray(SQLITE3_ASSOC);
            if (!$post) {
                http_response_code(404);
                die('Post not found.');
            }
            $replyStmt = $db->prepare('SELECT * FROM replies WHERE post_id = :post_id ORDER BY id ASC');
            $replyStmt->bindValue(':post_id', $post_id, SQLITE3_INTEGER);
            $replies = $replyStmt->execute();
            ?>
            <a class="back-link" href="./">Back to Main Board</a>
            <?php echo renderPost($post['id'], $post['title'], $post['message'], $post['media'] ?? null, false); ?>
            <form method="post">
                <input type="hidden" name="post_id" value="<?php echo $post_id; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <textarea name="message" placeholder="Reply message" maxlength="100000" required></textarea><br>
                <button type="submit">Post Reply</button>
            </form>
            <?php
            while ($reply = $replies->fetchArray(SQLITE3_ASSOC)) {
                echo renderReply($reply['message']);
            }
            ?>
        <?php else: ?>
            <div class="toggle-buttons">
                <button class="new-post-button">[NEW POST]</button>
                <button class="close-button">[X]</button>
            </div>
            <div class="form-container">
                <form enctype="multipart/form-data" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                    <input type="text" name="title" placeholder="Title" maxlength="20" required><br>
                    <textarea name="message" placeholder="Message" maxlength="100000" required></textarea><br>
                    <input type="file" name="media" accept="image/jpeg, image/png, image/gif, image/webp, video/webm, video/mp4"><br>
                    <button type="submit">Post</button>
                </form>
            </div>
            <div id="posts">
                <?php
                $stmt = $db->prepare("SELECT * FROM posts ORDER BY updated_at DESC LIMIT :limit OFFSET :offset");
                $stmt->bindValue(':limit', POSTS_PER_PAGE, SQLITE3_INTEGER);
                $stmt->bindValue(':offset', $offset, SQLITE3_INTEGER);
                $result = $stmt->execute();
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    echo renderPost($row['id'], $row['title'], $row['message'], $row['media'] ?? null);
                }
                ?>
            </div>
            <div class="pagination">
                <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                    <a href="?page=<?php echo $i; ?>" class="<?php echo ($i === $page) ? 'active' : ''; ?>"><?php echo $i; ?></a>
                <?php endfor; ?>
            </div>
        <?php endif; ?>
    </div>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            $('.new-post-button').click(function() {
                $(this).hide();
                $('.close-button').show();
                $('.form-container form').slideDown();
            });
            $('.close-button').click(function() {
                $(this).hide();
                $('.new-post-button').show();
                $('.form-container form').slideUp();
            });
            $(document).on('click', '.post-media', function() {
                $(this).toggleClass('expanded');
            });
        });
    </script>
</body>
</html>