<?php
session_start();
include 'db.php';

// ✅ Centralized Security Logging Function
function logSecurityEvent($conn, $event, $user_id = NULL) {
    $stmt = $conn->prepare("INSERT INTO security_logs (user_id, event, ip_address, user_agent, timestamp)
                            VALUES (?, ?, ?, ?, NOW())");
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

// ✅ Fix: Implement Role-Based Access Control (RBAC)
// Only allow access to logs if the user is an admin.
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    logSecurityEvent($conn, "Unauthorized access attempt to logs - User not an admin", $_SESSION['user_id'] ?? NULL);
    die("Unauthorized access! <a href='login.php'>Login</a>");
}

// ✅ Securely fetching user role using a prepared statement
$user_id = $_SESSION['user_id'];
$role_check = $conn->prepare("SELECT role FROM users WHERE id = ?");
$role_check->bind_param("i", $user_id);
$role_check->execute();
$result = $role_check->get_result();
$user = $result->fetch_assoc();

// ✅ Using a prepared statement to prevent SQL Injection
$sql = $conn->prepare("SELECT * FROM logs");
$sql->execute();
$logs = $sql->get_result();

// ✅ Log access to the logs page
logSecurityEvent($conn, "Admin viewed logs", $user_id);

// ❌ No logging if a database error occurs
if (!$logs) {
    // ✅ Fix: Do not expose SQL error details to the user
    echo "An error occurred while fetching logs. Please try again later.";
}
?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - Logs</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>System Logs</h2>

        <table border="1">
            <tr>
                <th>ID</th>
                <th>User ID</th>
                <th>Action</th>
                <th>Timestamp</th>
            </tr>
            <?php while ($log = $logs->fetch_assoc()) : ?>
                <tr>
                    <td><?php echo $log['id']; ?></td>
                    <td><?php echo $log['user_id']; ?></td>
                    <td><?php echo $log['action']; ?></td>
                    <td><?php echo $log['timestamp']; ?></td>
                </tr>
            <?php endwhile; ?>
        </table>

        <a href="admin_dashboard.php">Back to Dashboard</a>
    </div>
</body>
</html>

<?php $conn->close(); ?>
