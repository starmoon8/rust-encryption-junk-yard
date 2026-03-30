<?php
declare(strict_types=1);
// Configuration
const POSTS_PER_PAGE = 10;
const REPLIES_PER_PAGE = 1000; // Increased to effectively disable pagination for threads
const MAX_UPLOAD_SIZE = 30 * 1024 * 1024; // 30 MB
const MAX_PREVIEW_CHARS = 500; // Adjusted to better match truncation behavior
const MAIN_REPLIES_SHOWN = 5;
const MAX_REPLY_PREVIEW_CHARS = 500;
const ALLOWED_FILE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/webm', 'video/mp4'];
const BOARD_TITLE = '/b/ - Random';
const BOARD_SUBTITLE = '';
const ADMIN_PASSWORD = 'admin123'; // Change this for production
const MANAGE_COOKIE = 'messageboard_manage'; // The cookie that stores the password hash
const BOARD_NAME = 'b';
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
        locked INTEGER DEFAULT 0,
        deleted INTEGER DEFAULT 0,
        postiphash TEXT
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
        deleted INTEGER DEFAULT 0,
        postiphash TEXT,
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
// Migration: Add deleted to posts if not exists
$result = $db->query("PRAGMA table_info(posts)");
$has_deleted_posts = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'deleted') {
        $has_deleted_posts = true;
        break;
    }
}
if (!$has_deleted_posts) {
    try {
        $db->exec('ALTER TABLE posts ADD COLUMN deleted INTEGER DEFAULT 0');
    } catch (PDOException $e) {
        error_log('DB Error (migration deleted posts): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
// Migration: Add deleted to replies if not exists
$result = $db->query("PRAGMA table_info(replies)");
$has_deleted_replies = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'deleted') {
        $has_deleted_replies = true;
        break;
    }
}
if (!$has_deleted_replies) {
    try {
        $db->exec('ALTER TABLE replies ADD COLUMN deleted INTEGER DEFAULT 0');
    } catch (PDOException $e) {
        error_log('DB Error (migration deleted replies): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
// Migration: Add postiphash to posts if not exists
$result = $db->query("PRAGMA table_info(posts)");
$has_postiphash_posts = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'postiphash') {
        $has_postiphash_posts = true;
        break;
    }
}
if (!$has_postiphash_posts) {
    try {
        $db->exec('ALTER TABLE posts ADD COLUMN postiphash TEXT');
    } catch (PDOException $e) {
        error_log('DB Error (migration postiphash posts): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
// Migration: Add postiphash to replies if not exists
$result = $db->query("PRAGMA table_info(replies)");
$has_postiphash_replies = false;
while ($col = $result->fetch(PDO::FETCH_ASSOC)) {
    if ($col['name'] === 'postiphash') {
        $has_postiphash_replies = true;
        break;
    }
}
if (!$has_postiphash_replies) {
    try {
        $db->exec('ALTER TABLE replies ADD COLUMN postiphash TEXT');
    } catch (PDOException $e) {
        error_log('DB Error (migration postiphash replies): ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
    }
}
$canmanage = false;
$hashedcookie = $_COOKIE[MANAGE_COOKIE] ?? '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['managepassword'])) {
    if ($_POST['managepassword'] === ADMIN_PASSWORD) {
        setcookie(MANAGE_COOKIE, sha1(ADMIN_PASSWORD), 0);
        $canmanage = true;
    } else {
        $login_error = 'Wrong password.';
    }
} elseif ($hashedcookie === sha1(ADMIN_PASSWORD)) {
    $canmanage = true;
}
if (!$canmanage) {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo BOARD_TITLE . ' - Manage'; ?></title>
    <link rel="stylesheet" media="screen" href="/stylesheets/style.css?v=0">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=yes">
    <link rel="stylesheet" href="/stylesheets/font-awesome/css/font-awesome.min.css?v=0">
    <link rel="stylesheet" href="/static/flags/flags.css?v=0">
    <script type="text/javascript">var configRoot="/";var inMod = false ;var modRoot = "/" + (inMod ? "mod.php?/" : "");</script>
    <script type="text/javascript" src="/main.js?v=0" data-resource-version="0"></script>
    <script type="text/javascript" src="/js/jquery.min.js?v=0"></script>
    <script type="text/javascript" src="/js/inline-expanding.js?v=0"></script>
    <script type="text/javascript" src="/js/hide-form.js?v=0"></script>
    <script type="text/javascript" src="/js/style-select.js?v=0"></script>
</head>
<body>
    <header>
        <h1><?php echo BOARD_TITLE; ?></h1>
    </header>
    <hr>
    <div class="center"><form method="POST" action="mod.php">
    Password: <input type="password" name="managepassword" required> <input type="submit" value="Login">
    </form></div>
        <?php
        if (isset($login_error)) echo '<p>' . $login_error . '</p>';
        echo '</body></html>';
        exit;
}
function getUniqueFilename(string $directory, string $originalFilename): string {
    $extension = pathinfo($originalFilename, PATHINFO_EXTENSION);
    try {
        $basename = bin2hex(random_bytes(8));
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
    $stmt = $db->prepare('SELECT COUNT(*) FROM replies WHERE post_id = :post_id AND deleted = 0');
    $stmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
    $stmt->execute();
    return (int)$stmt->fetchColumn();
}
function formatTime(string $time): array {
    $timestamp = strtotime($time);
    $formatted = date('m/d/y (D) H:i:s', $timestamp);
    $datetime = date('Y-m-d\TH:i:sO', $timestamp);
    return ['formatted' => $formatted, 'datetime' => $datetime];
}
function renderMedia(?string $mediaPath, bool $isThumb = false): string {
    if (!$mediaPath) return '';
    $fileType = mime_content_type($mediaPath);
    $filename = basename($mediaPath);
    $size = filesize($mediaPath);
    $size_str = round($size / 1024, 2) . ' KB';
    $dims = '';
    $width = 250;
    $height = 250;
    $mediaTag = '';
    if (str_starts_with($fileType, 'image/')) {
        list($origW, $origH) = getimagesize($mediaPath);
        $dims = ", {$origW}x{$origH}";
        $ratio = min($width / $origW, $height / $origH, 1);
        $thumbW = (int)($origW * $ratio);
        $thumbH = (int)($origH * $ratio);
        $mediaTag = '<img class="post-image" src="' . htmlspecialchars($mediaPath) . '" style="width:' . $thumbW . 'px;height:' . $thumbH . 'px" alt="">';
    } elseif (str_starts_with($fileType, 'video/')) {
        // Assume default dims for video preview
        $mediaTag = '<video class="post-image" controls style="width:250px;height:250px"><source src="' . htmlspecialchars($mediaPath) . '" type="' . $fileType . '"></video>';
    }
    $fileinfo = '<p class="fileinfo"><span>File: <a href="' . htmlspecialchars($mediaPath) . '">' . htmlspecialchars($filename) . '</a></span><span class="unimportant">(' . $size_str . $dims . ', <a href="' . htmlspecialchars($mediaPath) . '" download="' . htmlspecialchars(pathinfo($filename, PATHINFO_FILENAME)) . '" title="Save as original filename">' . htmlspecialchars($filename) . '</a>)</span></p>';
    return '<div class="file">' . $fileinfo . '<a href="' . htmlspecialchars($mediaPath) . '" target="_blank">' . $mediaTag . '</a></div>';
}
function renderPost(int $id, string $title, string $message, ?string $mediaPath, string $name, string $created_at, bool $showReplyButton = true, bool $sticky = false, bool $locked = false, bool $deleted = false): string {
    global $db, $post_id;
    if ($deleted) {
        $title = 'Deleted';
        $message = '<i>Deleted</i>';
        $mediaPath = null;
        $name = 'Anonymous';
    }
    $timeInfo = formatTime($created_at);
    $replyCount = $showReplyButton ? getReplyCount($db, $id) : 0;
    $mediaHtml = renderMedia($mediaPath);
    $filesHtml = $mediaHtml ? '<div class="files ">' . $mediaHtml . '</div>' : '';
    $resLink = $showReplyButton ? 'mod.php?post_id=' . $id : '#';
    $qLink = $showReplyButton ? 'mod.php?post_id=' . $id . '#q' . $id : '#q' . $id;
    $hashLink = $showReplyButton ? 'mod.php?post_id=' . $id . '#' . $id : '#' . $id;
    $replyLinkHtml = $showReplyButton ? '<a href="mod.php?post_id=' . $id . '">[Reply]</a>' : '';
    $icons = '';
    if ($sticky) $icons .= '<img src="/stylesheets/sticky.png" alt="Sticky" title="Sticky">';
    if ($locked) $icons .= '<img src="/stylesheets/lock.png" alt="Locked" title="Locked">';
    $displayMessage = nl2br(htmlspecialchars($message));
    $toolongHtml = '';
    if ($showReplyButton && mb_strlen($message, 'UTF-8') > MAX_PREVIEW_CHARS) {
        $displayMessage = nl2br(htmlspecialchars(mb_substr($message, 0, MAX_PREVIEW_CHARS, 'UTF-8')));
        $toolongHtml = '<span class="toolong">Post too long. Click <a href="mod.php?post_id=' . $id . '#' . $id . '">here</a> to view the full text.</span>';
    }
    $omittedHtml = '';
    if ($showReplyButton && $replyCount > MAIN_REPLIES_SHOWN) {
        $omittedCount = $replyCount - MAIN_REPLIES_SHOWN;
        $omittedHtml = '<p class="omitted">' . $omittedCount . ' post' . ($omittedCount > 1 ? 's' : '') . ' omitted.</p>';
    }
    $repliesHtml = '';
    if ($showReplyButton && MAIN_REPLIES_SHOWN > 0 && $replyCount > 0) {
        $replyStmt = $db->prepare('SELECT * FROM replies WHERE post_id = :post_id AND deleted = 0 ORDER BY created_at DESC LIMIT :limit');
        $replyStmt->bindParam(':post_id', $id, PDO::PARAM_INT);
        $replyStmt->bindValue(':limit', MAIN_REPLIES_SHOWN, PDO::PARAM_INT);
        $replyStmt->execute();
        $replies = array_reverse($replyStmt->fetchAll(PDO::FETCH_ASSOC)); // Reverse to ASC for display
        foreach ($replies as $reply) {
            $repliesHtml .= renderReply($reply['id'], $reply['message'], $reply['name'] ?? 'Anonymous', $reply['created_at'], $id, (bool)$reply['deleted'], true);
        }
    }
    $modLinks = ' [<a href="mod.php?action=lock&id=' . $id . '">L</a> <a href="mod.php?action=sticky&id=' . $id . '">S</a> <a href="mod.php?action=delete&id=' . $id . '">D</a> <a href="mod.php?action=edit&id=' . $id . '">E</a>]';
    $intro = '<p class="intro"><span class="subject">' . htmlspecialchars($title) . '</span> <span class="name">' . htmlspecialchars($name) . '</span> <time datetime="' . $timeInfo['datetime'] . '">' . $timeInfo['formatted'] . '</time>&nbsp;<a class="post_no" id="post_no_' . $id . '" onclick="highlightReply(' . $id . ')" href="' . $hashLink . '">No.</a><a class="post_no" onclick="citeReply(' . $id . ')" href="' . $qLink . '">' . $id . '</a>' . $replyLinkHtml . $icons . $modLinks . '</p>';
    return '<div class="thread" id="thread_' . $id . '" data-board="' . BOARD_NAME . '">' . $filesHtml . 
           '<div class="post op" id="op_' . $id . '">' . $intro . '<div class="body">' . $displayMessage . $toolongHtml . '</div></div>' .
           $omittedHtml . $repliesHtml . '<br class="clear"/><hr/></div>';
}
function renderReply(int $reply_id, string $message, string $name, string $created_at, int $post_id, bool $deleted = false, bool $truncate = false): string {
    if ($deleted) {
        $message = '<i>Deleted</i>';
        $name = 'Anonymous';
    }
    $timeInfo = formatTime($created_at);
    $displayMessage = nl2br(htmlspecialchars($message));
    $toolongHtml = '';
    if ($truncate && mb_strlen($message, 'UTF-8') > MAX_REPLY_PREVIEW_CHARS) {
        $displayMessage = nl2br(htmlspecialchars(mb_substr($message, 0, MAX_REPLY_PREVIEW_CHARS, 'UTF-8')));
        $toolongHtml = '<span class="toolong">Post too long. Click <a href="mod.php?post_id=' . $post_id . '#reply_' . $reply_id . '">here</a> to view the full text.</span>';
    }
    $modLinks = ' [<a href="mod.php?action=delete_reply&id=' . $reply_id . '&post_id=' . $post_id . '">D</a> <a href="mod.php?action=edit_reply&id=' . $reply_id . '&post_id=' . $post_id . '">E</a>]';
    $intro = '<p class="intro"><a id="' . $reply_id . '" class="post_anchor"></a><span class="name">' . htmlspecialchars($name) . '</span> <time datetime="' . $timeInfo['datetime'] . '">' . $timeInfo['formatted'] . '</time>&nbsp;<a class="post_no" id="post_no_' . $reply_id . '" onclick="highlightReply(' . $reply_id . ')" href="mod.php?post_id=' . $post_id . '#' . $reply_id . '">No.</a><a class="post_no" onclick="citeReply(' . $reply_id . ')" href="mod.php?post_id=' . $post_id . '#q' . $reply_id . '">' . $reply_id . '</a>' . $modLinks . '</p>';
    return '<div class="post reply" id="reply_' . $reply_id . '">' . $intro . '<div class="files "></div><div class="body">' . $displayMessage . $toolongHtml . '</div></div><br/>';
}
function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        try {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        } catch (Exception $e) {
            handleError('Failed to generate CSRF token.');
        }
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
// Handle edit POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_submit'])) {
    $csrf_token_post = $_POST['csrf_token'] ?? '';
    if (!validateCsrfToken($csrf_token_post)) {
        error_log('Invalid CSRF token attempt', 3, $logsDir . 'app_errors.log');
        handleError('Invalid CSRF token', 403);
    }
    $new_message = trim($_POST['message'] ?? '');
    if (strlen($new_message) > 0) {
        $id = (int)$_POST['id'];
        $type = $_POST['type'];
        $post_id = (int)$_POST['post_id'];
        if ($type === 'post') {
            $updateStmt = $db->prepare('UPDATE posts SET message = :message WHERE id = :id');
        } else {
            $updateStmt = $db->prepare('UPDATE replies SET message = :message WHERE id = :id');
        }
        $updateStmt->execute([':message' => $new_message, ':id' => $id]);
    }
    header('Location: mod.php' . ($post_id ? '?post_id=' . $post_id : ''));
    exit;
}
// Handle posting new posts or replies
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['managepassword'])) {
    $csrf_token_post = $_POST['csrf_token'] ?? '';
    if (!validateCsrfToken($csrf_token_post)) {
        error_log('Invalid CSRF token attempt', 3, $logsDir . 'app_errors.log');
        handleError('Invalid CSRF token', 403);
    }
    $message = trim($_POST['body'] ?? '');
    if (strlen($message) === 0 || strlen($message) > 100000) {
        handleError('Comment is required and must be between 1 and 100000 characters.', 400);
    }
    $name = trim($_POST['name'] ?? '');
    if (strlen($name) === 0) {
        $name = 'Anonymous';
    }
    if (strlen($name) > 35) {
        handleError('Name must be at most 35 characters.', 400);
    }
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'];
    $hashedip = substr(sha1($ip), 0, 16);
    if (isset($_POST['thread'])) {
        // Handle new reply
        $post_id = filter_input(INPUT_POST, 'thread', FILTER_VALIDATE_INT);
        if ($post_id === false || $post_id <= 0) {
            handleError('Invalid post ID.', 400);
        }
        // Check if locked
        $lockStmt = $db->prepare('SELECT locked FROM posts WHERE id = :post_id AND deleted = 0');
        $lockStmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
        $lockStmt->execute();
        $lockRow = $lockStmt->fetch(PDO::FETCH_ASSOC);
        if (!$lockRow || $lockRow['locked'] == 1) {
            handleError('This thread is locked or deleted.', 403);
        }
        $db->beginTransaction();
        $stmt = $db->prepare('INSERT INTO replies (post_id, message, name, postiphash) VALUES (:post_id, :message, :name, :postiphash)');
        $stmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
        $stmt->bindParam(':message', $message, PDO::PARAM_STR);
        $stmt->bindParam(':name', $name, PDO::PARAM_STR);
        $stmt->bindParam(':postiphash', $hashedip, PDO::PARAM_STR);
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
        $title = trim($_POST['subject'] ?? '');
        if (strlen($title) === 0 || strlen($title) > 100) {
            handleError('Subject is required and must be between 1 and 100 characters.', 400);
        }
        $media = $_FILES['file'] ?? [];
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
        $stmt = $db->prepare('INSERT INTO posts (title, message, media, name, postiphash) VALUES (:title, :message, :media, :name, :postiphash)');
        $stmt->bindParam(':title', $title, PDO::PARAM_STR);
        $stmt->bindParam(':message', $message, PDO::PARAM_STR);
        $stmt->bindParam(':media', $mediaPath, PDO::PARAM_STR);
        $stmt->bindParam(':name', $name, PDO::PARAM_STR);
        $stmt->bindParam(':postiphash', $hashedip, PDO::PARAM_STR);
        $stmt->execute();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
}
// Handle mod actions
$action = $_GET['action'] ?? '';
$id = (int)($_GET['id'] ?? 0);
$post_id = (int)($_GET['post_id'] ?? 0);
if ($action && $canmanage) {
    if ($action === 'lock') {
        $stmt = $db->prepare('UPDATE posts SET locked = 1 - locked WHERE id = :id');
        $stmt->execute([':id' => $id]);
        header('Location: mod.php' . ($post_id ? '?post_id=' . $post_id : ''));
        exit;
    } elseif ($action === 'sticky') {
        $stmt = $db->prepare('UPDATE posts SET sticky = 1 - sticky WHERE id = :id');
        $stmt->execute([':id' => $id]);
        header('Location: mod.php' . ($post_id ? '?post_id=' . $post_id : ''));
        exit;
    } elseif ($action === 'delete') {
        $db->beginTransaction();
        $stmt = $db->prepare('UPDATE posts SET deleted = 1, reply_count = 0 WHERE id = :id');
        $stmt->execute([':id' => $id]);
        $stmt = $db->prepare('UPDATE replies SET deleted = 1 WHERE post_id = :id');
        $stmt->execute([':id' => $id]);
        // Delete media
        $mediaStmt = $db->prepare('SELECT media FROM posts WHERE id = :id');
        $mediaStmt->execute([':id' => $id]);
        $mediaRow = $mediaStmt->fetch(PDO::FETCH_ASSOC);
        $mediaPath = $mediaRow['media'] ?? null;
        if ($mediaPath && file_exists($mediaPath)) {
            unlink($mediaPath);
        }
        $db->commit();
        header('Location: mod.php' . ($post_id ? '?post_id=' . $post_id : ''));
        exit;
    } elseif ($action === 'delete_reply') {
        $db->beginTransaction();
        $stmt = $db->prepare('UPDATE replies SET deleted = 1 WHERE id = :id');
        $stmt->execute([':id' => $id]);
        // Recount replies
        $countStmt = $db->prepare('SELECT COUNT(*) as count FROM replies WHERE post_id = :post_id AND deleted = 0');
        $countStmt->execute([':post_id' => $post_id]);
        $countRow = $countStmt->fetch(PDO::FETCH_ASSOC);
        $actualCount = (int)($countRow['count'] ?? 0);
        $updateStmt = $db->prepare('UPDATE posts SET reply_count = :count WHERE id = :post_id');
        $updateStmt->execute([':count' => $actualCount, ':post_id' => $post_id]);
        $db->commit();
        header('Location: mod.php' . ($post_id ? '?post_id=' . $post_id : ''));
        exit;
    } elseif ($action === 'edit' || $action === 'edit_reply') {
        // Implement edit form
        if ($action === 'edit') {
            $stmt = $db->prepare('SELECT * FROM posts WHERE id = :id');
            $stmt->execute([':id' => $id]);
            $item = $stmt->fetch(PDO::FETCH_ASSOC);
            $type = 'post';
        } else {
            $stmt = $db->prepare('SELECT * FROM replies WHERE id = :id');
            $stmt->execute([':id' => $id]);
            $item = $stmt->fetch(PDO::FETCH_ASSOC);
            $type = 'reply';
        }
        if (!$item) {
            die('Item not found.');
        }
        ?>
        <form method="POST" action="mod.php">
            <input type="hidden" name="id" value="<?php echo $id; ?>">
            <input type="hidden" name="type" value="<?php echo $type; ?>">
            <input type="hidden" name="post_id" value="<?php echo $post_id; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            <textarea name="message" rows="10" cols="50"><?php echo htmlspecialchars($item['message']); ?></textarea><br>
            <input type="submit" name="edit_submit" value="Save">
        </form>
        <?php
        exit;
    }
}
// Pagination for main view
$totalPosts = (int)$db->query('SELECT COUNT(*) FROM posts WHERE deleted = 0')->fetchColumn();
$totalPages = max(1, (int)ceil($totalPosts / POSTS_PER_PAGE));
$page = max(1, (int)filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT) ?: 1);
if ($page > $totalPages) {
    $page = $totalPages;
}
$offset = ($page - 1) * POSTS_PER_PAGE;
$post_id = filter_input(INPUT_GET, 'post_id', FILTER_VALIDATE_INT) ?: null;
$active_page = $post_id ? 'thread' : 'index';
$script_vars = '<script type="text/javascript"> var active_page = "' . $active_page . '" , board_name = "' . BOARD_NAME . '"; ';
if ($post_id) $script_vars .= ', thread_id = "' . $post_id . '"';
$script_vars .= '; </script>';
$head_links = '<link rel="stylesheet" media="screen" href="/stylesheets/style.css?v=0">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=yes">
    <link rel="stylesheet" href="/stylesheets/font-awesome/css/font-awesome.min.css?v=0">
    <link rel="stylesheet" href="/static/flags/flags.css?v=0">
    <script type="text/javascript">var configRoot="/";var inMod = false ;var modRoot = "/" + (inMod ? "mod.php?/" : "");</script>
    <script type="text/javascript" src="/main.js?v=0" data-resource-version="0"></script>
    <script type="text/javascript" src="/js/jquery.min.js?v=0"></script>
    <script type="text/javascript" src="/js/inline-expanding.js?v=0"></script>
    <script type="text/javascript" src="/js/hide-form.js?v=0"></script>
    <script type="text/javascript" src="/js/style-select.js?v=0"></script>';
$meta_desc = '';
$meta_title = BOARD_TITLE;
$meta_image = '';
$og_url = '';
if ($post_id) {
    $stmt = $db->prepare('SELECT * FROM posts WHERE id = :id AND deleted = 0');
    $stmt->bindParam(':id', $post_id, PDO::PARAM_INT);
    $stmt->execute();
    $post = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($post) {
        $trunc_message = mb_substr($post['message'], 0, 200, 'UTF-8');
        $meta_desc = htmlspecialchars($trunc_message);
        $meta_title = '/b/ - ' . htmlspecialchars($trunc_message);
        $meta_image = $post['media'] ? 'https://' . $_SERVER['HTTP_HOST'] . '/' . htmlspecialchars($post['media']) : '';
        $og_url = 'https://' . $_SERVER['HTTP_HOST'] . '/mod.php?post_id=' . $post_id;
    }
}
$head_meta = '<meta name="description" content="' . $meta_desc . '" />
    <meta name="twitter:card" value="summary">
    <meta name="twitter:title" content="' . $meta_title . '" />
    <meta name="twitter:description" content="' . $meta_desc . '" />
    <meta name="twitter:image" content="' . $meta_image . '" />
    <meta property="og:title" content="' . $meta_title . '" />
    <meta property="og:type" content="article" />
    <meta property="og:image" content="' . $meta_image . '" />
    <meta property="og:description" content="' . $meta_desc . '" />';
if ($og_url) $head_meta .= '<meta property="og:url" content="' . $og_url . '" />';
$head_title = '<title>' . $meta_title . ' - Mod</title>';
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <?php echo $script_vars; ?>
    <?php echo $head_links; ?>
    <?php echo $head_meta; ?>
    <?php echo $head_title; ?>
</head>
<body>
    <header>
        <h1><?php echo BOARD_TITLE; ?> - Mod Mode</h1>
        <div class="subtitle"><?php echo BOARD_SUBTITLE; ?></div>
    </header>
    <?php if ($post_id): ?>
        <a name="top"></a>
        <div class="banner">Posting mode: Reply <a class="unimportant" href="mod.php">[Return]</a> <a class="unimportant" href="#bottom">[Go to bottom]</a></div>
    <?php endif; ?>
    <?php if (isset($_SESSION['error'])): ?>
        <p class="error"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></p>
    <?php endif; ?>
    <?php if ($post_id !== null && $post_id > 0): ?>
        <?php
        $stmt = $db->prepare('SELECT * FROM posts WHERE id = :id AND deleted = 0');
        $stmt->bindParam(':id', $post_id, PDO::PARAM_INT);
        $stmt->execute();
        $post = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$post) {
            handleError('Post not found.', 404);
        }
        $is_locked = ($post['locked'] ?? 0) == 1;
        // Fetch all replies (ASC order)
        $totalReplies = getReplyCount($db, $post_id);
        $replyStmt = $db->prepare('SELECT * FROM replies WHERE post_id = :post_id AND deleted = 0 ORDER BY created_at ASC');
        $replyStmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
        $replyStmt->execute();
        ?>
        <?php if (!$is_locked): ?>
        <form name="post" onsubmit="return doPost(this);" enctype="multipart/form-data" action="mod.php" method="post">
            <input type="hidden" name="thread" value="<?php echo $post_id; ?>">
            <input type="hidden" name="board" value="<?php echo BOARD_NAME; ?>">
            <table>
                <tr><th>Name</th><td><input type="text" name="name" size="25" maxlength="35" autocomplete="off"> </td></tr>
                <tr><th>Comment</th><td><textarea name="body" id="body" rows="5" cols="35" required></textarea><input accesskey="s" style="margin-left:2px;" type="submit" name="post" value="New Reply" /></td></tr>
            </table>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
        </form>
        <?php else: ?>
            <p>This thread is locked.</p>
        <?php endif; ?>
        <script type="text/javascript">rememberStuff();</script>
        <hr />
        <form name="postcontrols" action="mod.php" method="post">
            <input type="hidden" name="board" value="<?php echo BOARD_NAME; ?>" />
            <?php echo renderPost($post['id'], $post['title'], $post['message'], $post['media'] ?? null, $post['name'] ?? 'Anonymous', $post['created_at'], false, ($post['sticky'] ?? 0) == 1, ($post['locked'] ?? 0) == 1, ($post['deleted'] ?? 0) == 1); ?>
            <?php
            while ($reply = $replyStmt->fetch(PDO::FETCH_ASSOC)) {
                echo renderReply($reply['id'], $reply['message'], $reply['name'] ?? 'Anonymous', $reply['created_at'], $post_id, ($reply['deleted'] ?? 0) == 1, false);
            }
            ?>
            <div id="thread-interactions"><span id="thread-links"><a id="thread-return" href="mod.php">[Return]</a><a id="thread-top" href="#top">[Go to top]</a> </span><span id="thread-quick-reply"><a id="link-quick-reply" href="#">[Post a Reply]</a></span><div class="clearfix"></div>
        </form>
        <a name="bottom"></a>
    <?php else: ?>
        <form name="post" onsubmit="return doPost(this);" enctype="multipart/form-data" action="mod.php" method="post">
            <input type="hidden" name="board" value="<?php echo BOARD_NAME; ?>">
            <table>
                <tr><th>Name</th><td><input type="text" name="name" size="25" maxlength="35" autocomplete="off"> </td></tr>
                <tr><th>Subject</th><td><input style="float:left;" type="text" name="subject" size="25" maxlength="100" autocomplete="off" required><input accesskey="s" style="margin-left:2px;" type="submit" name="post" value="New Topic" /></td></tr>
                <tr><th>Comment</th><td><textarea name="body" id="body" rows="5" cols="35" required></textarea></td></tr>
                <tr id="upload"><th>File</th><td><input type="file" name="file" id="upload_file"><script type="text/javascript">if (typeof init_file_selector !== 'undefined') init_file_selector(1);</script></td></tr>
            </table>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
        </form>
        <script type="text/javascript">rememberStuff();</script>
        <hr />
        <form name="postcontrols" action="mod.php" method="post">
            <input type="hidden" name="board" value="<?php echo BOARD_NAME; ?>" />
            <?php
            $stmt = $db->prepare("SELECT * FROM posts WHERE deleted = 0 ORDER BY sticky DESC, updated_at DESC LIMIT :limit OFFSET :offset");
            $stmt->bindValue(':limit', POSTS_PER_PAGE, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                echo renderPost($row['id'], $row['title'], $row['message'], $row['media'] ?? null, $row['name'] ?? 'Anonymous', $row['created_at'], true, ($row['sticky'] ?? 0) == 1, ($row['locked'] ?? 0) == 1, ($row['deleted'] ?? 0) == 1);
            }
            ?>
        </form>
        <div class="pages">
            <?php
            $prevText = $page > 1 ? '<a href="mod.php?page=' . ($page - 1) . '">Previous</a>' : 'Previous';
            $nextText = $page < $totalPages ? '<a href="mod.php?page=' . ($page + 1) . '">Next</a>' : 'Next';
            echo $prevText . ' [';
            for ($i = 1; $i <= $totalPages; $i++) {
                if ($i === $page) {
                    echo '<a class="selected">' . $i . '</a>';
                } else {
                    echo '<a href="mod.php?page=' . $i . '">' . $i . '</a>';
                }
            }
            echo '] ' . $nextText;
            ?>
        </div>
    <?php endif; ?>
    <br clear="all">
    <footer> chessboard v1 - Mod </footer>
    <script type="text/javascript">ready();</script>
</body>
</html>