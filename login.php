<?php
// ✅ Set session security settings
session_set_cookie_params([
    'httponly' => true, // Prevents JavaScript access to session cookies (Mitigates XSS attacks)
    'secure' => true,   // Ensures cookies are only sent over HTTPS (Mitigates session hijacking)
    'samesite' => 'Strict' // Prevents CSRF attacks
]);

session_start();
include("db.php");

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

$error = "";
$max_attempts = 5; // Maximum failed attempts before blocking login
$lockout_time = 900; // Lock user out for 15 minutes after max attempts

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    // ✅ Input validation: Ensure username and password are not empty
    if (empty($username) || empty($password)) {
        $error = "Username and password are required!";
    } else {
        // ✅ Prevent brute-force by tracking failed login attempts
        $stmt = $conn->prepare("SELECT id, username, role, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $user_id = $user['id'];

            // ✅ Enforce lockout policy
            if ($conn->query("SHOW COLUMNS FROM users LIKE 'failed_attempts'")->num_rows) {
                $stmt = $conn->prepare("SELECT failed_attempts, last_attempt FROM users WHERE username = ?");
                $stmt->bind_param("s", $username);
                $stmt->execute();
                $extra_result = $stmt->get_result();
                $extra_data = $extra_result->fetch_assoc();

                $user['failed_attempts'] = $extra_data['failed_attempts'];
                $user['last_attempt'] = $extra_data['last_attempt'];

                if ($user['failed_attempts'] >= $max_attempts && (time() - strtotime($user['last_attempt'])) < $lockout_time) {
                    logSecurityEvent($conn, "Account Locked - Too many failed login attempts", $user_id);
                    $error = "Too many failed login attempts. Please try again after 15 minutes.";
                }
            }

            if (empty($error)) {
                if (password_verify($password, $user['password'])) {
                    // ✅ Secure session management
                    session_regenerate_id(true);

                    $_SESSION['user_id'] = $user_id;
                    $_SESSION['username'] = $user['username'];

                    // ✅ Strict role validation
                    $allowed_roles = ['admin', 'user'];
                    $_SESSION['role'] = in_array($user['role'], $allowed_roles) ? $user['role'] : 'user';

                    // ✅ Log successful login
                    logSecurityEvent($conn, "Successful Login", $user_id);

                    // ✅ Redirect based on role
                    header("Location: " . ($_SESSION['role'] === 'admin' ? "admin_dashboard.php" : "user_dashboard.php"));
                    exit();
                } else {
                    // ✅ Update failed login attempts
                    if (isset($user['failed_attempts'])) {
                        $update_stmt = $conn->prepare("UPDATE users SET failed_attempts = failed_attempts + 1, last_attempt = NOW() WHERE id = ?");
                        $update_stmt->bind_param("i", $user_id);
                        $update_stmt->execute();
                    }

                    // ✅ Log failed login attempt
                    logSecurityEvent($conn, "Failed Login - Incorrect password", $user_id);
                    $error = "Invalid username or password!";
                }
            }
        } else {
            // ✅ Log failed login attempt for unknown username
            logSecurityEvent($conn, "Failed Login - Unknown username: $username", NULL);
            $error = "Invalid username or password!";
        }
    }
}

// ✅ Log database connection errors
if ($conn->connect_error) {
    error_log("Database connection error: " . $conn->connect_error, 0);
}

?>




<?php
// session_start();
// include("db.php");
//
// $error = "";
// // $max_attempts = 5; // Maximum failed attempts before blocking login
// // $lockout_time = 900; // Lock user out for 15 minutes after max attempts
//
// if ($_SERVER["REQUEST_METHOD"] == "POST") {
//     $username = $_POST['username'];
//     $password = $_POST['password'];
//
//     // ❌ No failed login attempt logging (Brute-force attack possible)
//     $stmt = $conn->prepare("SELECT id, username, role, password FROM users WHERE username = ?");
//     $stmt->bind_param("s", $username);
//     $stmt->execute();
//     $result = $stmt->get_result();
//
//
//     if ($result->num_rows > 0) {
//         $user = $result->fetch_assoc();
//
//         // ✅ Password hashing, but session security is weak
//         if (password_verify($password, $user['password'])) {
//             $_SESSION['user_id'] = $user['id'];
//             $_SESSION['username'] = $user['username'];
//
//             // ❌ Role assignment without strong validation
//             $_SESSION['role'] = (in_array($user['role'], ['admin', 'user'])) ? $user['role'] : 'user';
//
//             // ❌ No session regeneration
//             if ($_SESSION['role'] === 'admin') {
//                 // ❌ Authentication token passed in URL (Exposed in logs, browser history)
//                 header("Location: admin_dashboard.php?user_id=" . $_SESSION['user_id'] . "&token=" . session_id());
//             } else {
//                 // ❌ Authentication token exposed in URL
//                 header("Location: user_dashboard.php?user_id=" . $_SESSION['user_id'] . "&token=" . session_id());
//             }
//             exit();
//         }
//     }
//
//     // ❌ No brute-force protection (Attacker can keep guessing passwords)
//     $error = "Invalid username or password!";
// }
// ?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Vulnerable Bank</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>Login to Your Account</h2>

        <?php if (!empty($error)) { echo "<p style='color:red;'>$error</p>"; } ?>

        <form method="POST" action="">
            <label for="username">Username:</label>
            <input type="text" name="username" required>

            <label for="password">Password:</label>
            <input type="password" name="password" required>

            <button type="submit">Login</button>
        </form>

        <p>Don't have an account? <a href="register.php">Register here</a></p> <!-- Register link added -->
    </div>
</body>
</html>
