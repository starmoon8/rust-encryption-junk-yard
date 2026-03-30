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
const MANAGE_COOKIE = 'messageboard_manage'; // The cookie that stores the password. You can fill this out with something random as an extra precaution
const LOCKFILE = 'messageboard.lock'; // The file that will be created when posting is turned off, and deleted when it is turned on
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
// Migrations for existing columns (created_at, name, sticky, locked) - assuming they are already handled as in original
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
$mode = $_GET['mode'] ?? '';
$canmanage = false;
if ($mode === 'manage') {
    $hashedcookie = $_COOKIE[MANAGE_COOKIE] ?? '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['managepassword'])) {
        if (sha1($_POST['managepassword']) === sha1(ADMIN_PASSWORD)) {
            setcookie(MANAGE_COOKIE, sha1(ADMIN_PASSWORD), 0);
            $canmanage = true;
        } else {
            // Show error in login form
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
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <header>
        <h1><?php echo BOARD_TITLE; ?></h1>
    </header>
    <hr>
    <div class="center"><form method="POST" action="?mode=manage">
    Password: <input type="password" name="managepassword" required> <input type="submit" value="Login">
    </form></div>
        <?php
        if (isset($login_error)) echo '<p>' . $login_error . '</p>';
        echo '</body></html>';
        exit;
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $page = (int)($_POST['page'] ?? 0);
        if (isset($_POST['delete'])) {
            $id = (int)$_POST['delete'];
            try {
                $db->beginTransaction();
                $stmt = $db->prepare('UPDATE posts SET deleted = 1, reply_count = 0 WHERE id = :id');
                $stmt->execute([':id' => $id]);
                $stmt = $db->prepare('UPDATE replies SET deleted = 1 WHERE post_id = :id');
                $stmt->execute([':id' => $id]);
                // Delete media if post
                $mediaStmt = $db->prepare('SELECT media FROM posts WHERE id = :id');
                $mediaStmt->execute([':id' => $id]);
                $mediaRow = $mediaStmt->fetch(PDO::FETCH_ASSOC);
                $mediaPath = $mediaRow['media'] ?? null;
                if ($mediaPath && file_exists($mediaPath)) {
                    unlink($mediaPath);
                }
                $db->commit();
            } catch (PDOException $e) {
                $db->rollBack();
                error_log('Delete post error: ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
            }
        }
        if (isset($_POST['delete_reply'])) {
            $id = (int)$_POST['delete_reply'];
            $post_id = (int)$_POST['post_id'];
            try {
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
            } catch (PDOException $e) {
                $db->rollBack();
                error_log('Delete reply error: ' . $e->getMessage(), 3, $logsDir . 'db_errors.log');
            }
        }
        if (isset($_POST['toggle_lock'])) {
            $id = (int)$_POST['toggle_lock'];
            $stmt = $db->prepare('UPDATE posts SET locked = 1 - locked WHERE id = :id');
            $stmt->execute([':id' => $id]);
        }
        if (isset($_POST['toggle_sticky'])) {
            $id = (int)$_POST['toggle_sticky'];
            $stmt = $db->prepare('UPDATE posts SET sticky = 1 - sticky WHERE id = :id');
            $stmt->execute([':id' => $id]);
        }
        if (isset($_POST['recount'])) {
            $id = (int)$_POST['recount'];
            $countStmt = $db->prepare('SELECT COUNT(*) as count FROM replies WHERE post_id = :id AND deleted = 0');
            $countStmt->execute([':id' => $id]);
            $countRow = $countStmt->fetch(PDO::FETCH_ASSOC);
            $actualCount = (int)($countRow['count'] ?? 0);
            $updateStmt = $db->prepare('UPDATE posts SET reply_count = :count WHERE id = :id');
            $updateStmt->execute([':count' => $actualCount, ':id' => $id]);
        }
        header('Location: ' . $_SERVER['PHP_SELF'] . '?mode=manage&page=' . $page);
        exit;
    }
    if (isset($_GET['togglelock'])) {
        if (file_exists(LOCKFILE)) {
            unlink(LOCKFILE);
        } else {
            file_put_contents(LOCKFILE, 'This board is locked.');
        }
        header('Location: ' . $_SERVER['PHP_SELF'] . '?mode=manage');
        exit;
    }
    // Fetch posts sorted like the board
    $postStmt = $db->query('SELECT * FROM posts ORDER BY sticky DESC, updated_at DESC');
    $posts = $postStmt->fetchAll(PDO::FETCH_ASSOC);
    // Fetch all replies and group by post_id
    $replyStmt = $db->query('SELECT * FROM replies ORDER BY created_at DESC');
    $allReplies = $replyStmt->fetchAll(PDO::FETCH_ASSOC);
    $groupedReplies = [];
    foreach ($allReplies as $reply) {
        $groupedReplies[$reply['post_id']][] = $reply;
    }
    // Pagination based on posts only (since replies are nested)
    $allPosts = count($posts);
    $totalpages = (int)ceil($allPosts / POSTS_PER_PAGE);
    $pagenumber = (int)($_GET['page'] ?? 0);
    if ($pagenumber < 0) $pagenumber = 0;
    if ($pagenumber >= $totalpages) $pagenumber = $totalpages - 1;
    $pagePosts = array_slice($posts, $pagenumber * POSTS_PER_PAGE, POSTS_PER_PAGE);
    $lockbutton = file_exists(LOCKFILE)
        ? '<a href="?mode=manage&togglelock"><button>Unlock Posting</button></a>'
        : '<a href="?mode=manage&togglelock"><button>Lock Posting</button></a>';
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo BOARD_TITLE . ' - Manage'; ?></title>
    <link rel="stylesheet" href="css/styles.css">
    <script>
        function toggleReplies(postId) {
            var replies = document.getElementById('replies-' + postId);
            var button = document.getElementById('toggle-' + postId);
            if (replies.style.display === 'none' || replies.style.display === '') {
                replies.style.display = 'table-row-group';
                button.textContent = 'Hide Replies';
            } else {
                replies.style.display = 'none';
                button.textContent = 'Show Replies';
            }
        }
    </script>
</head>
<body>
    <header>
        <h1><?php echo BOARD_TITLE; ?></h1>
    </header>
    <hr>
    <div class="center"><?php echo $lockbutton; ?></div>
    <br>
    <table class="manage-table">
    <tr class="manage-header"><th>#</th><th>Title</th><th>Name</th><th>Message</th><th>Time</th><th>Poster ID</th><th>Replies</th><th>Actions</th></tr>
    <?php
    foreach ($pagePosts as $idx => $p) {
        $id = $p['id'];
        $title = htmlspecialchars($p['title'] ?? '');
        $name = htmlspecialchars($p['name']);
        $raw_message = $p['message'];
        $display_message = mb_strlen($raw_message, 'UTF-8') > MAX_PREVIEW_CHARS ? mb_substr($raw_message, 0, MAX_PREVIEW_CHARS, 'UTF-8') . '...' : $raw_message;
        $message = htmlspecialchars($display_message);
        $time = $p['created_at'];
        $posterhash = $p['postiphash'] ?? '';
        $replies = $groupedReplies[$id] ?? [];
        $replyCount = count($replies);
        $row_class = ($idx % 2) ? "manage-row-even" : "manage-row-odd";
        $lock_text = $p['locked'] ? 'Unlock' : 'Lock';
        $sticky_text = $p['sticky'] ? 'Unsticky' : 'Sticky';
        $deleted = $p['deleted'] == 1;
        echo "<tr class=\"$row_class\">
                <td>$id</td>
                <td>$title</td>
                <td>$name</td>
                <td>$message</td>
                <td>$time</td>
                <td>$posterhash</td>
                <td>$replyCount</td>
                <td>
                    <form method='POST' action='?mode=manage'>
                        <input type='hidden' name='page' value='$pagenumber'>";
        if (!$deleted) {
            echo "<button type='submit' name='delete' value='$id'>Delete</button><br>";
        } else {
            echo "<i>Deleted</i><br>";
        }
        echo "<button type='submit' name='toggle_lock' value='$id'>$lock_text</button><br>
              <button type='submit' name='toggle_sticky' value='$id'>$sticky_text</button><br>
              <button type='submit' name='recount' value='$id'>Recount</button>
                    </form>";
        if ($replyCount > 0) {
            echo "<button id='toggle-$id' onclick='toggleReplies($id)'>Show Replies</button>";
        }
        echo "</td>
            </tr>";
        // Nested replies (hidden by default)
        if ($replyCount > 0) {
            echo "<tbody id='replies-$id' style='display:none;'>";
            foreach ($replies as $rIdx => $r) {
                $rId = $r['id'];
                $rName = htmlspecialchars($r['name']);
                $rRawMessage = $r['message'];
                $rDisplayMessage = mb_strlen($rRawMessage, 'UTF-8') > MAX_PREVIEW_CHARS ? mb_substr($rRawMessage, 0, MAX_PREVIEW_CHARS, 'UTF-8') . '...' : $rRawMessage;
                $rMessage = htmlspecialchars($rDisplayMessage);
                $rTime = $r['created_at'];
                $rPosterhash = $r['postiphash'] ?? '';
                $rDeleted = $r['deleted'] == 1;
                $rRowClass = (($idx + $rIdx + 1) % 2) ? "manage-reply-row-even" : "manage-reply-row-odd";
                echo "<tr class=\"$rRowClass\">
                        <td colspan='8' style='padding-left: 20px;'>
                            <strong>Reply #$rId</strong>: $rName - $rMessage ($rTime, Poster: $rPosterhash)
                            <form method='POST' action='?mode=manage' style='display:inline;'>
                                <input type='hidden' name='page' value='$pagenumber'>
                                <input type='hidden' name='post_id' value='$id'>";
                if (!$rDeleted) {
                    echo "<button type='submit' name='delete_reply' value='$rId'>Delete Reply</button>";
                } else {
                    echo "<i>Deleted</i>";
                }
                echo "</form>
                        </td>
                      </tr>";
            }
            echo "</tbody>";
        }
    }
    ?>
    </table>
    <div class="pagination">
        <?php
        if ($pagenumber > 0) {
            $prevpage = "?mode=manage&page=" . ($pagenumber - 1);
            echo '<a href="' . $prevpage . '">Previous</a>';
        } else {
            echo '<span>Previous</span>';
        }
        for ($i = 0; $i < $totalpages; $i++) {
            if ($i === $pagenumber) {
                echo '<span class="current">' . $i . '</span>';
            } else {
                $href = "?mode=manage&page=" . $i;
                echo '<a href="' . $href . '">' . $i . '</a>';
            }
        }
        if ($pagenumber < $totalpages - 1) {
            $nextpage = "?mode=manage&page=" . ($pagenumber + 1);
            echo '<a href="' . $nextpage . '">Next</a>';
        } else {
            echo '<span>Next</span>';
        }
        ?>
    </div><hr><div class="return-link">[<a href="index.php">Return</a>]</div><br clear="all">
</body>
</html>
<?php
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
function renderPost(int $id, string $title, string $message, ?string $mediaPath, string $name, bool $showReplyButton = true, bool $sticky = false, bool $locked = false, bool $deleted = false): string {
    global $db;
    if ($deleted) {
        $title = 'Deleted';
        $message = '<i>Deleted</i>';
        $mediaPath = null;
        $name = 'Anonymous';
    }
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
    $replyLink = $showReplyButton ? '<a href="index.php?post_id=' . $id . '">[Reply]</a>' : '';
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
        $replyStmt = $db->prepare('SELECT * FROM replies WHERE post_id = :post_id AND deleted = 0 ORDER BY id DESC LIMIT :limit');
        $replyStmt->bindParam(':post_id', $id, PDO::PARAM_INT);
        $replyStmt->bindValue(':limit', MAIN_REPLIES_SHOWN, PDO::PARAM_INT);
        $replyStmt->execute();
        while ($reply = $replyStmt->fetch(PDO::FETCH_ASSOC)) {
            $repliesHtml .= renderReply($reply['id'], $reply['message'], $reply['name'] ?? 'Anonymous', $id, (bool)$reply['deleted']);
        }
    }
    $icons = '';
    if ($sticky) $icons .= '<img src="css/sticky.png" alt="Sticky" title="Sticky">';
    if ($locked) $icons .= '<img src="css/lock.png" alt="Locked" title="Locked">';
    return ($showReplyButton ? '<hr>' : '') . '
        <div class="post op">
            ' . ($mediaTag ? '<div class="file">' . $mediaTag . '</div>' . $fileinfo : '') . '
            <div class="intro"><span class="subject">' . htmlspecialchars($title) . '</span> <span class="name">' . htmlspecialchars($name) . '</span> ' . $replyLink . ' ' . $icons . '</div>
            <div class="body">' . nl2br(htmlspecialchars($displayMessage)) . ' ' . $readMoreLink . '</div>
            ' . ($mediaTag ? '<br class="clear">' : '') . '
            ' . $omittedHtml . $repliesHtml . '
        </div>
    ';
}
function renderReply(int $reply_id, string $message, string $name, int $post_id, bool $deleted = false): string {
    if ($deleted) {
        $message = '<i>Deleted</i>';
        $name = 'Anonymous';
    }
    return '<div class="post reply" id="r' . $reply_id . '">
        <div class="intro"><span class="name">' . htmlspecialchars($name) . '</span></div>
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
    $hashedcookie = $_COOKIE[MANAGE_COOKIE] ?? '';
    if (file_exists(LOCKFILE) && $hashedcookie !== sha1(ADMIN_PASSWORD)) {
        handleError('Submissions are currently locked.');
    }
    $csrf_token_post = $_POST['csrf_token'] ?? '';
    if (!validateCsrfToken($csrf_token_post)) {
        error_log('Invalid CSRF token attempt', 3, $logsDir . 'app_errors.log');
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
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'];
    $hashedip = substr(sha1($ip), 0, 16);
    if (isset($_POST['post_id'])) {
        // Handle new reply
        $post_id = filter_input(INPUT_POST, 'post_id', FILTER_VALIDATE_INT);
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
// Pagination for main view
$totalPosts = (int)$db->query('SELECT COUNT(*) FROM posts WHERE deleted = 0')->fetchColumn();
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
        $stmt = $db->prepare('SELECT * FROM posts WHERE id = :id AND deleted = 0');
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
        $replyStmt = $db->prepare('SELECT * FROM replies WHERE post_id = :post_id AND deleted = 0 ORDER BY id DESC LIMIT :limit OFFSET :offset');
        $replyStmt->bindParam(':post_id', $post_id, PDO::PARAM_INT);
        $replyStmt->bindValue(':limit', REPLIES_PER_PAGE, PDO::PARAM_INT);
        $replyStmt->bindValue(':offset', $replyOffset, PDO::PARAM_INT);
        $replyStmt->execute();
        ?>
        <a class="back-link" href="./">[Return]</a>
        <?php if (!$is_locked): ?>
        <form method="post" action="" enctype="multipart/form-data">
            <table class="post-table">
                <tbody>
                    <tr><th>Name</th><td><input type="text" name="name" size="25" maxlength="35" autocomplete="off" placeholder="Anonymous"></td></tr>
                    <tr><th>Reply</th><td><textarea name="message" rows="5" cols="35" required></textarea></td></tr>
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
        <?php echo renderPost($post['id'], $post['title'], $post['message'], $post['media'] ?? null, $post['name'] ?? 'Anonymous', false, ($post['sticky'] ?? 0) == 1, ($post['locked'] ?? 0) == 1, ($post['deleted'] ?? 0) == 1); ?>
        <?php
        while ($reply = $replyStmt->fetch(PDO::FETCH_ASSOC)) {
            echo renderReply($reply['id'], $reply['message'], $reply['name'] ?? 'Anonymous', $post_id, ($reply['deleted'] ?? 0) == 1);
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
                    <tr><th>Subject</th><td><input type="text" name="title" size="25" maxlength="100" autocomplete="off" required></td></tr>
                    <tr><th>Message</th><td><textarea name="message" rows="5" cols="35" required></textarea></td></tr>
                    <tr><th>File</th><td><input type="file" name="media" accept="image/jpeg, image/png, image/gif, image/webp, video/webm, video/mp4"></td></tr>
                    <tr><th></th><td><input type="submit" value="Post" /></td></tr>
                </tbody>
            </table>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
        </form>
        <hr>
        <div id="posts">
            <?php
            $stmt = $db->prepare("SELECT * FROM posts WHERE deleted = 0 ORDER BY sticky DESC, updated_at DESC LIMIT :limit OFFSET :offset");
            $stmt->bindValue(':limit', POSTS_PER_PAGE, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                echo renderPost($row['id'], $row['title'], $row['message'], $row['media'] ?? null, $row['name'] ?? 'Anonymous', true, ($row['sticky'] ?? 0) == 1, ($row['locked'] ?? 0) == 1, ($row['deleted'] ?? 0) == 1);
            }
            ?>
        </div>
        <div class="pagination">
            <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                <a href="?page=<?php echo $i; ?>" class="<?php echo ($i === $page) ? 'current' : ''; ?>"><?php echo $i; ?></a>
            <?php endfor; ?>
        </div>
    <?php endif; ?>
    <div class="return-link">[<a href="?mode=manage">Manage</a>]</div>
    <br clear="all">
</body>
</html>