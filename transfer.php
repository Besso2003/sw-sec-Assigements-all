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

// Enforce session-based authentication (Fix Broken Access Control)
$user_id = $_SESSION['user_id'];

$message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $from_account = $_POST['from_account'];
    $to_account = $_POST['to_account'];
    $amount = $_POST['amount'];

    // ✅ Check if the user is not trying to transfer to the same account
    if ($from_account === $to_account) {
        logSecurityEvent($conn, "Attempted transfer from and to the same account: $from_account", $user_id);
        $message = "Error: You cannot transfer to the same account.";
    } else {
        // Validate that 'from_account' belongs to the logged-in user
        $from_account_check = $conn->prepare("SELECT * FROM accounts WHERE account_number = ? AND user_id = ?");
        $from_account_check->bind_param("si", $from_account, $user_id);
        $from_account_check->execute();
        $from_account_result = $from_account_check->get_result();

        if ($from_account_result->num_rows == 0) {
            // Log unauthorized access attempt
            logSecurityEvent($conn, "Unauthorized transfer attempt from account: $from_account", $user_id);
            $message = "Error: You are not authorized to transfer from this account.";
        } else {
            // Step 2: Check if the 'to_account' exists
            $to_account_check = $conn->prepare("SELECT * FROM accounts WHERE account_number = ?");
            $to_account_check->bind_param("s", $to_account);
            $to_account_check->execute();
            $to_account_result = $to_account_check->get_result();

            if ($to_account_result->num_rows == 0) {
                // Log invalid transfer to non-existent account
                logSecurityEvent($conn, "Transfer attempt to invalid account: $to_account", $user_id);
                $message = "Error: To account does not exist.";
            } else {
                // ✅ Fix: Implement transaction control to prevent inconsistent money transfers
                $conn->begin_transaction();

                try {
                    // Step 3: Check if the 'from_account' has sufficient balance
                    $from_account_data = $from_account_result->fetch_assoc();
                    if ($from_account_data['balance'] < $amount) {
                        // Log failed transaction due to insufficient balance
                        logSecurityEvent($conn, "Failed transaction due to insufficient balance in account: $from_account", $user_id);
                        throw new Exception("Error: Insufficient balance in the from account.");
                    }

                    // Step 4: Proceed with the transfer securely
                    $update_from = $conn->prepare("UPDATE accounts SET balance = balance - ? WHERE account_number = ?");
                    $update_from->bind_param("ds", $amount, $from_account);
                    $update_from->execute();

                    $update_to = $conn->prepare("UPDATE accounts SET balance = balance + ? WHERE account_number = ?");
                    $update_to->bind_param("ds", $amount, $to_account);
                    $update_to->execute();

                    // ✅ Fix: Ensure transaction and logs are committed together
                    $insert_transaction = $conn->prepare("INSERT INTO transactions (user_id, from_account, to_account, amount, type, date)
                                                           VALUES (?, ?, ?, ?, 'transfer', NOW())");
                    $insert_transaction->bind_param("issd", $user_id, $from_account, $to_account, $amount);
                    $insert_transaction->execute();

                    $insert_log = $conn->prepare("INSERT INTO logs (user_id, action, timestamp)
                                                  VALUES (?, ?, NOW())");
                    $log_message = "Transferred $amount from $from_account to $to_account";
                    $insert_log->bind_param("is", $user_id, $log_message);
                    $insert_log->execute();

                    // ✅ Fix: Ensure transaction is committed only if all queries succeed
                    $conn->commit();
                    $message = "Transfer successful!";

                    // Log successful transaction
                    logSecurityEvent($conn, "Successful transfer of $amount from $from_account to $to_account", $user_id);
                } catch (Exception $e) {
                    // ✅ Fix: Rollback if any query fails to prevent partial money transfer
                    $conn->rollback();
                    // Log the error
                    logSecurityEvent($conn, "Transaction failed: " . $e->getMessage(), $user_id);
                    $message = $e->getMessage();
                }
            }
        }
    }
}

// ✅ Fetch user's accounts securely (FIXED: SQL Injection)
$query = $conn->prepare("SELECT * FROM accounts WHERE user_id = ?");
$query->bind_param("i", $user_id);
$query->execute();
$accounts = $query->get_result();

// ✅ Fix: Hide internal database error details
if (!$accounts) {
    // Log database error
    logSecurityEvent($conn, "Database error while fetching accounts", $user_id);
    die("Error retrieving account information. Please try again later.");
}
logSecurityEvent($conn, "User accessed Transfer", $user_id);
?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Transfer Money</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>Transfer Money</h2>

        <?php if ($message) { echo "<p style='color:green;'>$message</p>"; } ?>

        <form method="POST">
            <label for="from_account">From Account:</label>
            <select name="from_account" required>
                <?php while ($account = $accounts->fetch_assoc()) : ?>
                    <option value="<?php echo $account['account_number']; ?>">
                        <?php echo $account['account_number'] . " - $" . $account['balance']; ?>
                    </option>
                <?php endwhile; ?>
            </select>

            <label for="to_account">To Account:</label>
            <input type="text" name="to_account" required>

            <label for="amount">Amount:</label>
            <input type="number" name="amount" min="1" required>

            <button type="submit">Transfer</button>
        </form>

        <a href="user_dashboard.php">Back to Dashboard</a>
    </div>
</body>
</html>

<?php $conn->close(); ?>