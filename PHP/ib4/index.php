<?php
declare(strict_types=1);
// Configuration
const POSTS_PER_PAGE = 10;
const REPLIES_PER_PAGE = 10; // New: for reply pagination
const MAX_UPLOAD_SIZE = 30 * 1024 * 1024; // 30 MB
const MAX_PREVIEW_CHARS = 1000;
const MAIN_REPLIES_SHOWN = 5;
const MAX_REPLY_PREVIEW_CHARS = 1000;
const ALLOWED_FILE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/webm', 'video/mp4'];
const BOARD_TITLE = 'Message Board';
const BOARD_SUBTITLE = 'General discussion, images, and videos';
// Admin password (plaintext for dev; secure later)
const ADMIN_PASSWORD = 'admin123'; // Change this for production
// Error logging setup
ini_set('log_errors', '1');
ini_set('error_log', 'logs/php_errors.log'); // Directory must exist and be writable
session_start([
    'cookie_lifetime' => 86400,
    'cookie_httponly' => true,
    'cookie_secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
    'cookie_samesite' => 'Strict',
]);
// Regenerate session ID to prevent session fixation
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}
// Handle login/logout
if (isset($_GET['admin']) && $_GET['admin'] === 'logout') {
    unset($_SESSION['admin_logged_in']);
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}
if (isset($_POST['admin_login'])) {
    $password = $_POST['password'] ?? '';
    if ($password === ADMIN_PASSWORD) {
        $_SESSION['admin_logged_in'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = 'Invalid password.';
    }
}
$is_admin = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
$uploadsDir = 'uploads/';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0755, true);
}
$logsDir = 'logs/';
if (!is_dir($logsDir)) {
    mkdir($logsDir, 0755, true);
}
if (!is_writable($logsDir) || !is_writable($uploadsDir)) {
    die('Directories not writable. Check permissions.');
}
try {
    $db = new PDO('sqlite:' . $uploadsDir . 'message_board.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // Enable WAL mode for better concurrency and recovery
    $db->exec('PRAGMA journal_mode = WAL');
    // Enable foreign key enforcement for data integrity
    $db->exec('PRAGMA foreign_keys = ON');
    // Set synchronous to FULL for durability
    $db->exec('PRAGMA synchronous = FULL');
    // Enable secure delete for privacy/reliability
    $db->exec('PRAGMA secure_delete = ON');
    // Set busy timeout to handle concurrency
    $db->exec('PRAGMA busy_timeout = 5000');
} catch (PDOException $e) {
    error_log('DB Error: ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    die('Database connection failed: ' . $e->getMessage());
}
// Create posts table if it doesn't exist
try {
    $db->exec('CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        media TEXT,
        reply_count INTEGER DEFAULT 0,
        name TEXT DEFAULT \'Anonymous\',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        sticky INTEGER DEFAULT 0,
        locked INTEGER DEFAULT 0
    )');
} catch (PDOException $e) {
    error_log('DB Error (create posts): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
}
// Create replies table if it doesn't exist (with CASCADE for deletes)
try {
    $db->exec('CREATE TABLE IF NOT EXISTS replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        name TEXT DEFAULT \'Anonymous\',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    )');
} catch (PDOException $e) {
    error_log('DB Error (create replies): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
}
// Create trigger to update timestamp on post update
try {
    $db->exec('CREATE TRIGGER IF NOT EXISTS update_timestamp
               AFTER UPDATE ON posts
               FOR EACH ROW
               WHEN NEW.updated_at <= OLD.updated_at
               BEGIN
                   UPDATE posts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
               END');
} catch (PDOException $e) {
    error_log('DB Error (create trigger): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
}
// Add indexes for performance
try {
    $db->exec('CREATE INDEX IF NOT EXISTS idx_posts_updated_at ON posts(updated_at DESC)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_replies_post_id ON replies(post_id)');
} catch (PDOException $e) {
    error_log('DB Error (indexes): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
}
// Migration: Add created_at to posts if not exists
$result = $db->query("PRAGMA table_info(posts)");
$has_created_at_posts = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'created_at') {
        $has_created_at_posts = true;
        break;
    }
}
if (!$has_created_at_posts) {
    try {
        $db->beginTransaction();
        $db->exec('ALTER TABLE posts RENAME TO posts_old');
        $db->exec('CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            media TEXT,
            reply_count INTEGER DEFAULT 0,
            name TEXT DEFAULT \'Anonymous\',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            sticky INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0
        )');
        $db->exec('INSERT INTO posts (id, title, message, media, reply_count, name, updated_at, created_at)
                   SELECT id, title, message, media, reply_count, name, updated_at, updated_at FROM posts_old');
        $db->exec('DROP TABLE posts_old');
        $db->commit();
    } catch (PDOException $e) {
        $db->rollBack();
        error_log('DB Error (migration created_at posts): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
// Migration: Add created_at to replies if not exists
$result = $db->query("PRAGMA table_info(replies)");
$has_created_at_replies = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'created_at') {
        $has_created_at_replies = true;
        break;
    }
}
if (!$has_created_at_replies) {
    try {
        $db->beginTransaction();
        $db->exec('ALTER TABLE replies RENAME TO replies_old');
        $db->exec('CREATE TABLE replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            name TEXT DEFAULT \'Anonymous\',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
        )');
        $db->exec('INSERT INTO replies (id, post_id, message, name, created_at)
                   SELECT id, post_id, message, name, CURRENT_TIMESTAMP FROM replies_old');
        $db->exec('DROP TABLE replies_old');
        $db->commit();
    } catch (PDOException $e) {
        $db->rollBack();
        error_log('DB Error (migration created_at replies): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
// Migration: Add name to posts if not exists
$result = $db->query("PRAGMA table_info(posts)");
$has_name_posts = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'name') {
        $has_name_posts = true;
        break;
    }
}
if (!$has_name_posts) {
    try {
        $db->exec('ALTER TABLE posts ADD COLUMN name TEXT DEFAULT \'Anonymous\'');
    } catch (PDOException $e) {
        error_log('DB Error (migration name posts): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
// Migration: Add name to replies if not exists
$result = $db->query("PRAGMA table_info(replies)");
$has_name_replies = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'name') {
        $has_name_replies = true;
        break;
    }
}
if (!$has_name_replies) {
    try {
        $db->exec('ALTER TABLE replies ADD COLUMN name TEXT DEFAULT \'Anonymous\'');
    } catch (PDOException $e) {
        error_log('DB Error (migration name replies): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
// Migration: Add sticky to posts if not exists
$result = $db->query("PRAGMA table_info(posts)");
$has_sticky = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'sticky') {
        $has_sticky = true;
        break;
    }
}
if (!$has_sticky) {
    try {
        $db->exec('ALTER TABLE posts ADD COLUMN sticky INTEGER DEFAULT 0');
    } catch (PDOException $e) {
        error_log('DB Error (migration sticky): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
// Migration: Add locked to posts if not exists
$result = $db->query("PRAGMA table_info(posts)");
$has_locked = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'locked') {
        $has_locked = true;
        break;
    }
}
if (!$has_locked) {
    try {
        $db->exec('ALTER TABLE posts ADD COLUMN locked INTEGER DEFAULT 0');
    } catch (PDOException $e) {
        error_log('DB Error (migration locked): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
// Handle mod actions (delete, sticky, lock, recount)
if ($is_admin && isset($_GET['action'])) {
    $action = $_GET['action'];
    $target_id = (int)($_GET['id'] ?? 0);
    if ($target_id > 0) {
        if ($action === 'delete_post') {
            try {
                $db->beginTransaction();
                // Get media path to delete file after DB delete
                $mediaStmt = $db->prepare('SELECT media FROM posts WHERE id = :id');
                $mediaStmt->bindParam(':id', $target_id, PDO::PARAM_INT);
                $mediaStmt->execute();
                $mediaRow = $mediaStmt->fetch(PDO::FETCH_ASSOC);
                $mediaPath = $mediaRow['media'] ?? null;
                // Delete post (replies cascade via FOREIGN KEY)
                $stmt = $db->prepare('DELETE FROM posts WHERE id = :id');
                $stmt->bindParam(':id', $target_id, PDO::PARAM_INT);
                $stmt->execute();
                $db->commit();
                // Now delete file if exists
                if ($mediaPath && file_exists($mediaPath)) {
                    if (!unlink($mediaPath)) {
                        error_log('Failed to delete media: ' . $mediaPath, 3, $logsDir . 'app_errors.log');
                    }
                }
            } catch (PDOException $e) {
                $db->rollBack();
                error_log('Delete post error: ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
            }
        } elseif ($action === 'delete_reply') {
            try {
                $db->beginTransaction();
                $stmt = $db->prepare('DELETE FROM replies WHERE id = :id');
                $stmt->bindParam(':id', $target_id, PDO::PARAM_INT);
                $stmt->execute();
                // Decrement reply_count
                $post_id = (int)($_GET['post_id'] ?? 0);
                if ($post_id > 0) {
                    $bumpStmt = $db->prepare('UPDATE posts SET reply_count = reply_count - 1 WHERE id = :post_id AND reply_count > 0');
                    $bumpStmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
                    $bumpStmt->execute();
                }
                $db->commit();
            } catch (PDOException $e) {
                $db->rollBack();
                error_log('Delete reply error: ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
            }
        } elseif ($action === 'sticky') {
            $stmt = $db->prepare('UPDATE posts SET sticky = NOT sticky WHERE id = :id');
            $stmt->bindParam(':id', $target_id, PDO::PARAM_INT);
            $stmt->execute();
        } elseif ($action === 'lock') {
            $stmt = $db->prepare('UPDATE posts SET locked = NOT locked WHERE id = :id');
            $stmt->bindParam(':id', $target_id, PDO::PARAM_INT);
            $stmt->execute();
        } elseif ($action === 'recount') {
            // Recount replies for this post
            $countStmt = $db->prepare('SELECT COUNT(*) as count FROM replies WHERE post_id = :id');
            $countStmt->bindParam(':id', $target_id, PDO::PARAM_INT);
            $countStmt->execute();
            $countRow = $countStmt->fetch(PDO::FETCH_ASSOC);
            $actualCount = (int)($countRow['count'] ?? 0);
            $updateStmt = $db->prepare('UPDATE posts SET reply_count = :count WHERE id = :id');
            $updateStmt->bindParam(':count', $actualCount, PDO::PARAM_INT);
            $updateStmt->bindParam(':id', $target_id, PDO::PARAM_INT);
            $updateStmt->execute();
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . (isset($_GET['post_id']) ? '?post_id=' . $_GET['post_id'] : ''));
    exit;
}
function getUniqueFilename(string $directory, string $originalFilename): string {
    $extension = pathinfo($originalFilename, PATHINFO_EXTENSION);
    try {
        $basename = bin2hex(random_bytes(8)); // Random hex for security, ignore original name
    } catch (Exception $e) {
        handleError('Failed to generate secure filename.');
    }
    $newFilename = $basename . ($extension ? '.' . $extension : '');
    $counter = 1;
    while (file_exists($directory . $newFilename)) {
        $newFilename = $basename . '-' . $counter . ($extension ? '.' . $extension : '');
        $counter++;
    }
    return $newFilename;
}
function getReplyCount(PDO $db, int $post_id): int {
    $stmt = $db->prepare('SELECT reply_count FROM posts WHERE id = :post_id');
    $stmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return (int)($row['reply_count'] ?? 0);
}
function renderPost(int $id, string $title, string $message, ?string $mediaPath, string $name, bool $showReplyButton = true, bool $sticky = false, bool $locked = false): string {
    global $db, $is_admin, $post_id;
    $replyCount = $showReplyButton ? getReplyCount($db, $id) : 0;
    $mediaTag = '';
    $fileinfo = '';
    if ($mediaPath) {
        $fileType = mime_content_type($mediaPath);
        $filename = basename($mediaPath);
        $size = filesize($mediaPath);
        $size_str = round($size / 1024, 1) . ' KB';
        $dims = '';
        if (str_starts_with($fileType, 'image/')) {
            list($width, $height) = getimagesize($mediaPath);
            $dims = ", {$width}x{$height}";
            $mediaTag = '<img src="' . htmlspecialchars($mediaPath) . '" class="post-image" alt="">';
        } elseif (str_starts_with($fileType, 'video/')) {
            $mediaTag = '<video class="post-image" controls><source src="' . htmlspecialchars($mediaPath) . '" type="' . $fileType . '"></video>';
        }
        $fileinfo = '<p class="fileinfo">File: <a href="' . htmlspecialchars($mediaPath) . '">' . htmlspecialchars($filename) . '</a> (' . $size_str . $dims . ')</p>';
    }
    $replyLink = '';
    if ($showReplyButton) {
        $replyLink = '<a href="index.php?post_id=' . $id . '">[Reply]</a>';
    }
    $displayMessage = $message;
    $readMoreLink = '';
    if ($showReplyButton && mb_strlen($message, 'UTF-8') > MAX_PREVIEW_CHARS) {
        $displayMessage = mb_substr($message, 0, MAX_PREVIEW_CHARS, 'UTF-8');
        $readMoreLink = '<a href="index.php?post_id=' . $id . '">[Read more]</a>';
    }
    $omittedHtml = '';
    if ($showReplyButton && $replyCount > MAIN_REPLIES_SHOWN) {
        $omittedCount = $replyCount - MAIN_REPLIES_SHOWN;
        $omittedHtml = '<span class="omitted">' . $omittedCount . ' post' . ($omittedCount > 1 ? 's' : '') . ' omitted.</span>';
    }
    $repliesHtml = '';
    if ($showReplyButton && MAIN_REPLIES_SHOWN > 0 && $replyCount > 0) {
        $replyStmt = $db->prepare('SELECT * FROM replies WHERE post_id = :post_id ORDER BY id DESC LIMIT :limit');
        $replyStmt->bindParam(':post_id', $id, PDO::PARAM_INT);
        $replyStmt->bindValue(':limit', MAIN_REPLIES_SHOWN, PDO::PARAM_INT);
        $replyStmt->execute();
        while ($reply = $replyStmt->fetch(PDO::FETCH_ASSOC)) {
            $replyMessage = $reply['message'];
            $replyName = $reply['name'] ?? 'Anonymous';
            $replyDisplay = $replyMessage;
            $replyMoreLink = '';
            if (mb_strlen($replyMessage, 'UTF-8') > MAX_REPLY_PREVIEW_CHARS) {
                $replyDisplay = mb_substr($replyMessage, 0, MAX_REPLY_PREVIEW_CHARS, 'UTF-8');
                $replyMoreLink = '<a href="index.php?post_id=' . $id . '#r' . $reply['id'] . '">[Read more]</a>';
            }
            $repliesHtml .= '<div class="post reply">
                <div class="intro"><span class="name">' . htmlspecialchars($replyName) . '</span></div>
                <div class="body">' . nl2br(htmlspecialchars($replyDisplay)) . ' ' . $replyMoreLink . '</div>
            </div>';
        }
    }
    $icons = '';
    if ($sticky) {
        $icons .= '<img src="css/sticky.png" alt="Sticky" title="Sticky">';
    }
    if ($locked) {
        $icons .= '<img src="css/lock.png" alt="Locked" title="Locked">';
    }
    $modLinks = '';
    if ($is_admin && !$showReplyButton) { // Only in thread view
        $modLinks = ' [<a href="?action=delete_post&id=' . $id . '">D</a>] [<a href="?action=sticky&id=' . $id . '">S</a>] [<a href="?action=lock&id=' . $id . '">L</a>] [<a href="?action=recount&id=' . $id . '">R</a>]';
    }
    return ($showReplyButton ? '<hr>' : '') . '
        <div class="post op">
            ' . ($mediaTag ? '<div class="file">' . $mediaTag . '</div>' . $fileinfo : '') . '
            <div class="intro"><span class="subject">' . htmlspecialchars($title) . '</span> <span class="name">' . htmlspecialchars($name) . '</span> ' . $replyLink . ' ' . $icons . $modLinks . '</div>
            <div class="body">' . nl2br(htmlspecialchars($displayMessage)) . ' ' . $readMoreLink . '</div>
            ' . ($mediaTag ? '<br class="clear">' : '') . '
            ' . $omittedHtml . $repliesHtml . '
        </div>
    ';
}
function renderReply(int $reply_id, string $message, string $name, int $post_id): string {
    global $is_admin;
    $modLinks = '';
    if ($is_admin) {
        $modLinks = ' [<a href="?action=delete_reply&id=' . $reply_id . '&post_id=' . $post_id . '">D</a>]';
    }
    return '<div class="post reply" id="r' . $reply_id . '">
        <div class="intro"><span class="name">' . htmlspecialchars($name) . '</span>' . $modLinks . '</div>
        <div class="body">' . nl2br(htmlspecialchars($message)) . '</div>
    </div>';
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
function handleError(string $message, int $code = 400) {
    http_response_code($code);
    $_SESSION['error'] = $message;
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}
$csrf_token = generateCsrfToken();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_token_post = $_POST['csrf_token'] ?? '';
    if (!validateCsrfToken($csrf_token_post)) {
        error_log('Invalid CSRF token attempt', 3, $logsDir . 'app_errors.log'); // Optional: Log app-level CSRF failures
        handleError('Invalid CSRF token', 403);
    }
    $message = trim($_POST['message'] ?? '');
    if (strlen($message) === 0 || strlen($message) > 100000) {
        handleError('Message is required and must be between 1 and 100000 characters.', 400);
    }
    $name = trim($_POST['name'] ?? '');
    if (strlen($name) === 0) {
        $name = 'Anonymous';
    }
    if (strlen($name) > 35) {
        handleError('Name must be at most 35 characters.', 400);
    }
    if (isset($_POST['post_id'])) {
        // Handle new reply
        $post_id = filter_input(INPUT_POST, 'post_id', FILTER_VALIDATE_INT);
        if ($post_id === false || $post_id <= 0) {
            handleError('Invalid post ID.', 400);
        }
        // Check if locked
        $lockStmt = $db->prepare('SELECT locked FROM posts WHERE id = :post_id');
        $lockStmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
        $lockStmt->execute();
        $lockRow = $lockStmt->fetch(PDO::FETCH_ASSOC);
        if (($lockRow['locked'] ?? 0) == 1 && !$is_admin) {
            handleError('This thread is locked.', 403);
        }
        $db->beginTransaction();
        $stmt = $db->prepare('INSERT INTO replies (post_id, message, name) VALUES (:post_id, :message, :name)');
        $stmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
        $stmt->bindParam(':message', $message, PDO::PARAM_STR);
        $stmt->bindParam(':name', $name, PDO::PARAM_STR);
        $stmt->execute();
        // Increment reply_count and bump
        $bumpStmt = $db->prepare('UPDATE posts SET reply_count = reply_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = :post_id');
        $bumpStmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
        $bumpStmt->execute();
        $db->commit();
        header('Location: ' . $_SERVER['PHP_SELF'] . '?post_id=' . $post_id);
        exit;
    } else {
        // Handle new post
        $title = trim($_POST['title'] ?? '');
        if (strlen($title) === 0 || strlen($title) > 100) {
            handleError('Title is required and must be between 1 and 100 characters.', 400);
        }
        $media = $_FILES['media'] ?? [];
        $mediaPath = null;
        if (isset($media['tmp_name']) && $media['size'] > 0) {
            $tmpName = $media['tmp_name'];
            if (!is_uploaded_file($tmpName)) {
                handleError('Invalid file upload.', 400);
            }
            $fileType = mime_content_type($tmpName);
            if (!in_array($fileType, ALLOWED_FILE_TYPES, true)) {
                handleError('Invalid file type.', 400);
            }
            if ($media['size'] > MAX_UPLOAD_SIZE) {
                handleError('File too large.', 400);
            }
            if (str_starts_with($fileType, 'image/')) {
                if (!getimagesize($tmpName)) {
                    handleError('Invalid image.', 400);
                }
            }
            $uniqueFilename = getUniqueFilename($uploadsDir, $media['name']);
            $mediaPath = $uploadsDir . $uniqueFilename;
            if (!move_uploaded_file($tmpName, $mediaPath)) {
                error_log('Failed to move uploaded file: ' . $tmpName, 3, $logsDir . 'app_errors.log');
                handleError('Failed to move uploaded file.', 500);
            }
        }
        $stmt = $db->prepare('INSERT INTO posts (title, message, media, name) VALUES (:title, :message, :media, :name)');
        $stmt->bindParam(':title', $title, PDO::PARAM_STR);
        $stmt->bindParam(':message', $message, PDO::PARAM_STR);
        $stmt->bindParam(':media', $mediaPath, PDO::PARAM_STR);
        $stmt->bindParam(':name', $name, PDO::PARAM_STR);
        $stmt->execute();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
}
// Pagination for main view
$totalPosts = (int)$db->query('SELECT COUNT(*) FROM posts')->fetchColumn();
$totalPages = max(1, (int)ceil($totalPosts / POSTS_PER_PAGE));
$page = max(1, (int)filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT) ?: 1);
if ($page > $totalPages) {
    $page = $totalPages;
}
$offset = ($page - 1) * POSTS_PER_PAGE;
$post_id = filter_input(INPUT_GET, 'post_id', FILTER_VALIDATE_INT) ?: null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo BOARD_TITLE; ?></title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <header>
        <h1><?php echo BOARD_TITLE; ?></h1>
        <div class="subtitle"><?php echo BOARD_SUBTITLE; ?></div>
    </header>
    <hr>
    <?php if (isset($_SESSION['error'])): ?>
        <p class="error"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></p>
    <?php endif; ?>
    <?php if ($post_id !== null && $post_id > 0): ?>
        <?php
        $stmt = $db->prepare('SELECT * FROM posts WHERE id = :id');
        $stmt->bindParam(':id', $post_id, PDO::PARAM_INT);
        $stmt->execute();
        $post = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$post) {
            handleError('Post not found.', 404);
        }
        $is_locked = ($post['locked'] ?? 0) == 1;
        // Pagination for replies
        $totalReplies = getReplyCount($db, $post_id);
        $totalReplyPages = max(1, (int)ceil($totalReplies / REPLIES_PER_PAGE));
        $replyPage = max(1, (int)filter_input(INPUT_GET, 'rpage', FILTER_VALIDATE_INT) ?: 1);
        if ($replyPage > $totalReplyPages) {
            $replyPage = $totalReplyPages;
        }
        $replyOffset = ($replyPage - 1) * REPLIES_PER_PAGE;
        $replyStmt = $db->prepare('SELECT * FROM replies WHERE post_id = :post_id ORDER BY id DESC LIMIT :limit OFFSET :offset');
        $replyStmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
        $replyStmt->bindValue(':limit', REPLIES_PER_PAGE, PDO::PARAM_INT);
        $replyStmt->bindParam(':offset', $replyOffset, PDO::PARAM_INT);
        $replyStmt->execute();
        ?>
        <a class="back-link" href="./">[Return]</a>
        <?php if (!$is_locked): ?>
        <form method="post" action="" enctype="multipart/form-data">
            <table class="post-table">
                <tbody>
                    <tr><th>Name</th><td><input type="text" name="name" size="25" maxlength="35" autocomplete="off" placeholder="Anonymous"></td></tr>
                    <tr><th>Reply</th><td><textarea name="message" rows="5" cols="35"></textarea></td></tr>
                    <tr><th></th><td><input type="submit" value="Post" /></td></tr>
                </tbody>
            </table>
            <input type="hidden" name="post_id" value="<?php echo $post_id; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
        </form>
        <?php else: ?>
            <p>This thread is locked.</p>
        <?php endif; ?>
        <hr>
        <?php echo renderPost($post['id'], $post['title'], $post['message'], $post['media'] ?? null, $post['name'] ?? 'Anonymous', false, ($post['sticky'] ?? 0) == 1, ($post['locked'] ?? 0) == 1); ?>
        <?php
        while ($reply = $replyStmt->fetch(PDO::FETCH_ASSOC)) {
            echo renderReply($reply['id'], $reply['message'], $reply['name'] ?? 'Anonymous', $post_id);
        }
        ?>
        <div class="pagination">
            <?php for ($i = 1; $i <= $totalReplyPages; $i++): ?>
                <a href="?post_id=<?php echo $post_id; ?>&rpage=<?php echo $i; ?>" class="<?php echo ($i === $replyPage) ? 'current' : ''; ?>"><?php echo $i; ?></a>
            <?php endfor; ?>
        </div>
    <?php else: ?>
        <form method="post" action="" enctype="multipart/form-data">
            <table class="post-table">
                <tbody>
                    <tr><th>Name</th><td><input type="text" name="name" size="25" maxlength="35" autocomplete="off" placeholder="Anonymous"></td></tr>
                    <tr><th>Subject</th><td><input type="text" name="title" size="25" maxlength="100" autocomplete="off"></td></tr>
                    <tr><th>Message</th><td><textarea name="message" rows="5" cols="35"></textarea></td></tr>
                    <tr><th>File</th><td><input type="file" name="media" accept="image/jpeg, image/png, image/gif, image/webp, video/webm, video/mp4"></td></tr>
                    <tr><th></th><td><input type="submit" value="Post" /></td></tr>
                </tbody>
            </table>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
        </form>
        <hr>
        <div id="posts">
            <?php
            $stmt = $db->prepare("SELECT * FROM posts ORDER BY sticky DESC, updated_at DESC LIMIT :limit OFFSET :offset");
            $stmt->bindValue(':limit', POSTS_PER_PAGE, PDO::PARAM_INT);
            $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                echo renderPost($row['id'], $row['title'], $row['message'], $row['media'] ?? null, $row['name'] ?? 'Anonymous', true, ($row['sticky'] ?? 0) == 1, ($row['locked'] ?? 0) == 1);
            }
            ?>
        </div>
        <div class="pagination">
            <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                <a href="?page=<?php echo $i; ?>" class="<?php echo ($i === $page) ? 'current' : ''; ?>"><?php echo $i; ?></a>
            <?php endfor; ?>
        </div>
    <?php endif; ?>
    <?php if (!$is_admin): ?>
        <div style="position: fixed; bottom: 10px; left: 10px;">
            <a href="?admin=login" style="font-size: 12px;">[Admin]</a>
        </div>
    <?php else: ?>
        <div style="position: fixed; bottom: 10px; left: 10px;">
            <a href="?admin=logout" style="font-size: 12px;">[Logout]</a>
        </div>
    <?php endif; ?>
    <?php if (isset($_GET['admin']) && $_GET['admin'] === 'login' && !$is_admin): ?>
        <form method="post">
            <input type="password" name="password" placeholder="Admin Password" required>
            <button type="submit" name="admin_login" value="1">Login</button>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            <?php if (isset($login_error)) echo '<p>' . $login_error . '</p>'; ?>
        </form>
    <?php endif; ?>
</body>
</html>