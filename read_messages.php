<?php
session_start();
include 'db.php';

// ✅ Centralized Security Logging Function
function logSecurityEvent($conn, $event, $user_id = NULL) {
    $stmt = $conn->prepare("INSERT INTO security_logs (user_id, event, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, NOW())");
    if ($stmt) {
        $ip_address = getClientIP();  // Get the client IP address
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';  // Get the user agent
        $stmt->bind_param("isss", $user_id, $event, $ip_address, $user_agent);
        $stmt->execute();
        $stmt->close();
    } else {
        error_log("SECURITY LOG FAILURE: Failed to log event - " . $event . " for User ID: " . ($user_id ?? "unknown"));
    }
}

// Function to get client IP
function getClientIP() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        return $_SERVER['REMOTE_ADDR'];
    }
}

// Only admins allowed
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    logSecurityEvent($conn, "Unauthorized access to view messages", $_SESSION['user_id'] ?? NULL);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

// ✅ Log access to the admin messages view
logSecurityEvent($conn, "Admin viewed messages", $_SESSION['user_id']);

// ✅ Secure Message Retrieval with Prepared Statements
$limit = 10;  // Limit the number of messages displayed
$page = 1; // Always load page 1
$offset = ($page - 1) * $limit;

$query = $conn->prepare("SELECT * FROM messages LIMIT ? OFFSET ?");
$query->bind_param("ii", $limit, $offset);
$query->execute();
$messages = $query->get_result();

// Handle the reply submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reply'])) {
    $message_id = $_POST['message_id'];
    $reply = $_POST['reply'];

    // Prepare statement to insert the reply into the database
    $stmt = $conn->prepare("INSERT INTO message_replies (message_id, admin_id, reply_text) VALUES (?, ?, ?)");
    $stmt->bind_param("iis", $message_id, $_SESSION['user_id'], $reply);
    $stmt->execute();
    $stmt->close();

    logSecurityEvent($conn, "Admin replied to message ID: $message_id", $_SESSION['user_id']);

    // Redirect to avoid re-posting the form on page refresh
    header("Location: " . $_SERVER['REQUEST_URI']); // Reload the page
    exit; // Prevent further code execution
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - User Messages</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>User Messages</h2>

        <table border="1">
            <tr>
                <th>User ID</th>
                <th>Message</th>
                <th>Reply</th>
            </tr>
            <?php while ($message = $messages->fetch_assoc()) : ?>
                <tr>
                    <td><?php echo htmlspecialchars($message['user_id']); ?></td>
                    <td><?php echo htmlspecialchars($message['message']); ?></td>
                    <td>
                        <form action="read_messages.php" method="POST">
                            <input type="hidden" name="message_id" value="<?php echo $message['id']; ?>">
                            <textarea name="reply" placeholder="Enter reply..."></textarea>
                            <button type="submit">Reply</button>
                        </form>

                        <!-- Displaying existing replies -->
                        <h4>Replies:</h4>
                        <?php
                        $message_id = $message['id'];
                        $replyQuery = $conn->prepare("SELECT * FROM message_replies WHERE message_id = ?");
                        $replyQuery->bind_param("i", $message_id);
                        $replyQuery->execute();
                        $replies = $replyQuery->get_result();
                        while ($reply = $replies->fetch_assoc()) {
                            echo "<p><strong>Admin:</strong> " . htmlspecialchars($reply['reply_text']) . "</p>";
                        }
                        ?>
                    </td>
                </tr>
            <?php endwhile; ?>
        </table>

        <a href="admin_dashboard.php">Back to Dashboard</a>
    </div>
</body>
</html>

<?php $conn->close(); ?>
