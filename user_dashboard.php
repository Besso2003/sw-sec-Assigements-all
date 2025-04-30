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

// ✅ Implement Role-Based Access Control (RBAC) to restrict access
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'user') {
    // Log unauthorized access attempt
    logSecurityEvent($conn, "Unauthorized access attempt", $_SESSION['user_id'] ?? null);
    die("Unauthorized access! <a href='login.php'>Login</a>");
}

// Enforce session-based authentication (Fix Broken Access Control)
$user_id = $_SESSION['user_id'];

// FIX: Use prepared statements to prevent SQL Injection
$query = $conn->prepare("SELECT * FROM users WHERE id = ?");
$query->bind_param("i", $user_id);
$query->execute();
$result = $query->get_result();

if (!$result) {
    // ✅ FIX: Hide detailed database errors from users
    logSecurityEvent($conn, "Unauthorized attempt to access user data (User ID: $user_id)", $user_id);
    die("An error occurred. Please try again later."); // Show generic error message
}

$user = $result->fetch_assoc();

// ✅ Log access to the user dashboard
logSecurityEvent($conn, "Accessed user dashboard", $user_id);

?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Banking System</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>Welcome, <?php echo $user['username']; ?>!</h2>
        <p>Your role: <?php echo $user['role']; ?></p>

        <h3>Your Accounts</h3>
        <?php
        // Fetch account balance (No validation, SQL Injection risk)
        $balanceQuery = $conn->query("SELECT * FROM accounts WHERE user_id = '$user_id'");
        while ($account = $balanceQuery->fetch_assoc()) {
            echo "<p>Account: " . $account['account_number'] . " - Balance: $" . $account['balance'] . "</p>";
        }
        ?>

        <h3>Actions</h3>
        <ul>
            <li><a href="transfer.php">Transfer Money</a></li>
            <li><a href="statement.php">View Statement</a></li>
            <li><a href="complaints.php">Submit a Complaint</a></li>
            <li><a href="message.php">Send Message to Admin</a></li>
        </ul>

        <a href="logout.php">Logout</a>
    </div>
</body>
</html>

<?php $conn->close(); ?>
