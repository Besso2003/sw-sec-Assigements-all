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
    logSecurityEvent($conn, "Unauthorized access to reply endpoint");
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

$message_id = isset($_POST['message_id']) ? intval($_POST['message_id']) : 0;
$admin_reply = isset($_POST['admin_reply']) ? trim($_POST['admin_reply']) : '';

if ($message_id <= 0 || empty($admin_reply)) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid input']);
    exit;
}

// Prepare the SQL query
$query = "UPDATE messages SET admin_reply = ?, reply_date = NOW() WHERE id = ?";
$stmt = $conn->prepare($query);

// Debugging: Check if the statement was prepared successfully
if (!$stmt) {
    error_log("Prepare failed: " . $conn->error); // Log if query preparation fails
    echo json_encode(['status' => 'error', 'message' => 'Prepare failed']);
    exit;
}

$stmt->bind_param("si", $admin_reply, $message_id);

// Execute the query and check for errors
if ($stmt->execute()) {
    logSecurityEvent($conn, "Admin replied to message $message_id", $_SESSION['user_id']);
    echo json_encode(['status' => 'success', 'message' => 'Reply sent successfully']);
} else {
    error_log("Execution failed: " . $stmt->error); // Log if query execution fails
    echo json_encode(['status' => 'error', 'message' => 'Execution failed']);
}

$stmt->close();
$conn->close();
?>
