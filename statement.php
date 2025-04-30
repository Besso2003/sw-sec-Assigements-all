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

// ❌ No logging of unauthorized access attempts
if (!isset($_SESSION['user_id'])) {
    logSecurityEvent($conn, "Unauthorized access attempt - No session", NULL);
    die("Unauthorized access! <a href='login.php'>Login</a>");
}

$user_id = $_SESSION['user_id'];

// ✅ Fix: Verify if user_id exists in the database to prevent stale sessions
// ❌ No logging of invalid or hijacked sessions
$checkUser = $conn->prepare("SELECT id FROM users WHERE id = ?");
$checkUser->bind_param("i", $user_id);
$checkUser->execute();
$result = $checkUser->get_result();
if ($result->num_rows === 0) {
    logSecurityEvent($conn, "Unauthorized access attempt - User does not exist", $user_id);
    die("Unauthorized access! User does not exist.");
}

// ✅ FIX: Use prepared statements to prevent SQL Injection
// ✅ Fix: Implement pagination to prevent excessive data retrieval
$limit = 10; // Number of transactions per page
$page = isset($_GET['page']) ? (int) $_GET['page'] : 1;
$offset = ($page - 1) * $limit;

$query = $conn->prepare("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC LIMIT ? OFFSET ?");
$query->bind_param("iii", $user_id, $limit, $offset);
$query->execute();
$result = $query->get_result();

// Log the successful retrieval of transactions
logSecurityEvent($conn, "User Successfully viewed statements", $user_id);
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Transaction Statement</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>Your Transaction History</h2>

        <table border="1">
            <tr>
                <th>Date</th>
                <th>From Account</th>
                <th>To Account</th>
                <th>Amount</th>
                <th>Type</th>
            </tr>
            <?php while ($transaction = $result->fetch_assoc()) : ?>
                <tr>
                    <td><?php echo $transaction['date']; ?></td>
                    <td><?php echo $transaction['from_account']; ?></td>
                    <td><?php echo $transaction['to_account']; ?></td>
                    <td>$<?php echo $transaction['amount']; ?></td>
                    <td><?php echo $transaction['type']; ?></td>
                </tr>
            <?php endwhile; ?>
        </table>

        <a href="user_dashboard.php">Back to Dashboard</a>
    </div>
</body>
</html>

<?php $conn->close(); ?>
