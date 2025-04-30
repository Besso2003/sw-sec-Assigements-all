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


// ✅ Role-Based Access Control (RBAC)
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'user') {
    logSecurityEvent($conn, "Unauthorized access attempt - User ID: " . ($_SESSION['user_id'] ?? "unknown") . " tried to send a message without permission.", $_SESSION['user_id'] ?? NULL);
    die("Unauthorized access! Only users can send messages. <a href='login.php'>Login</a>");
}

$message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user_id = $_SESSION['user_id'];
    $user_message = $_POST['user_message'];

    // ✅ Verify database connection
    if (!$conn) {
        die("Database connection failed. Please try again later.");
    }

    // ✅ Verify if user_id exists in the database
    $stmt = $conn->prepare("SELECT id FROM users WHERE id = ?");
    if (!$stmt) {
        error_log("SQL Error select users: " . $conn->error);
        die("Prepare failed: " . $conn->error);
    }
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 0) {
        logSecurityEvent($conn, "Unauthorized access - User ID does not exist", $user_id);
        die("Unauthorized access! User does not exist.");
    }
    $stmt->close();

    // ✅ Enforce message length limit
    if (strlen($user_message) > 500) {
        logSecurityEvent($conn, "Message rejected - Too long", $user_id);
        die("Message is too long. Maximum 500 characters allowed.");
    }

    // ✅ Implement rate limiting to prevent spam
    $stmt = $conn->prepare("SELECT sent_at FROM messages WHERE user_id = ? ORDER BY sent_at DESC LIMIT 1");
    if (!$stmt) {
        error_log("SQL Error select messages : " . $conn->error);
        die("Prepare failed: " . $conn->error);
    }
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
         $row = $result->fetch_assoc();
         $last_time = strtotime($row['sent_at']);
         if (time() - $last_time < 10) { // Enforce 10-second delay between messages
             logSecurityEvent($conn, "Rate limit exceeded - User ID: $user_id", $user_id);
             die("Please wait before sending another message.");
         }
    }
    $stmt->close();

    // ✅ Use prepared statements for inserting messages
    $stmt = $conn->prepare("INSERT INTO messages (user_id, message, sent_at) VALUES (?, ?, NOW())");
    if (!$stmt) {
        error_log("SQL Error insert messages : " . $conn->error);
        die("An error occurred. Please try again.");
    }
    $stmt->bind_param("is", $user_id, $user_message);
    $stmt->execute();
    $stmt->close();

    // ✅ Log the action including the message content
    $stmt = $conn->prepare("INSERT INTO logs (user_id, action, timestamp) VALUES (?, ?, NOW())");
    if (!$stmt) {
        error_log("SQL Error insert logs: " . $conn->error);
        die("An error occurred. Please try again.");
    }
    $log_action = "Sent a message: " . $user_message;  // Log the message content
    $stmt->bind_param("is", $user_id, $log_action);
    $stmt->execute();
    $stmt->close();

    $message = "Message sent successfully!";
}

// Ensure $user_id is set before using it
if (isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    logSecurityEvent($conn, "User viewed message page", $user_id);
}
?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Send Message</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>Send a Message to Admin</h2>

        <?php if ($message) { echo "<p style='color:green;'>$message</p>"; } ?>

        <form method="POST">
            <label for="user_message">Your Message:</label>
            <textarea name="user_message" required></textarea>

            <button type="submit">Send</button>
        </form>

        <a href="user_dashboard.php">Back to Dashboard</a>
    </div>
</body>
</html>
