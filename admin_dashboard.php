<?php
include 'db.php';
session_start();


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

// ✅ Function to get client IP
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
// Only allow access if the user is an admin.
// ❌ No logging for unauthorized access attempts
// ✅ Secure Role-Based Access Control (RBAC) with logging
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    logSecurityEvent($conn, "Unauthorized access attempt - User not an admin");
    die("Unauthorized access! Admins only. <a href='login.php'>Login</a>");
}

// ✅ Fix: Update PHPMailer to a secure and supported version
// ❌ No error logging if PHPMailer fails
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/vendor/autoload.php'; // Ensure correct path

$mail = new PHPMailer(true); // Use PHPMailer with exception handling

// ✅ Echo the installed PHPMailer version
// $composerFile = __DIR__ . '/vendor/composer/installed.json';
//
// if (file_exists($composerFile)) {
//     $composerData = json_decode(file_get_contents($composerFile), true);
//
//     if (isset($composerData['packages'])) { // Check if 'packages' key exists
//         foreach ($composerData['packages'] as $package) {
//             if (isset($package['name']) && $package['name'] === 'phpmailer/phpmailer') {
//                 echo "<p>PHPMailer Version: " . $package['version'] . "</p>";
//                 break;
//             }
//         }
//     } else {
//         echo "<p>Could not determine PHPMailer version. JSON structure may be different.</p>";
//     }
// } else {
//     echo "<p>Could not determine PHPMailer version. installed.json not found.</p>";
// }

// ✅ Fix: Security Misconfiguration: Revealing system version information to attackers
//echo "Warning: This system is running outdated PHP and MySQL versions!";

// ✅ FIX: Use a prepared statement to prevent SQL Injection
$user_id = $_SESSION['user_id'];
$sql = $conn->prepare("SELECT * FROM users WHERE id = ?");
$sql->bind_param("i", $user_id); // Bind user ID securely as an integer
$sql->execute();
$result = $sql->get_result();

// ❌ No logging for SQL failures
if (!$result) {
    // ✅ Log SQL failure to database for security auditing
    logSecurityEvent($conn, "Database query failure: Failed to fetch user data");

    // ✅ Log to system error logs for debugging (web server logs or PHP error log)
    error_log("Database query failed for user ID: $user_id");

    // ✅ Show a generic message to the user (Avoid exposing errors)
    echo "Error fetching user data. Please try again later.";
}
$user = $result->fetch_assoc();

// ✅ Log access to the user dashboard
logSecurityEvent($conn, "Accessed admin dashboard", $user_id);

// ✅ Fix: Use a secure and up-to-date JavaScript library
echo '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>';
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
            <li><a href="read_messages.php">Read Messages</a></li>
            <li><a href="logs.php">View Logs</a></li>
        </ul>

        <a href="logout.php">Logout</a>
    </div>
</body>
</html>

<?php $conn->close(); ?>
