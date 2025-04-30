<?php
include 'db.php';

// Check the database connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// ✅ Centralized Security Logging Function
function logSecurityEvent($conn, $event, $username = NULL, $email = NULL) {
    $stmt = $conn->prepare("INSERT INTO security_logs (event, username, email, ip_address, user_agent, timestamp)
                            VALUES (?, ?, ?, ?, ?, NOW())");
    if ($stmt) {
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';
        $stmt->bind_param("sssss", $event, $username, $email, $ip_address, $user_agent);
        $stmt->execute();
        $stmt->close();
    } else {
        error_log("SECURITY LOG FAILURE: Failed to log event - " . $event . " for User: " . ($username ?? "unknown"));
    }
}

$message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // ✅ Fix: Input validation and sanitization
    $username = filter_var(trim($_POST['username']), FILTER_SANITIZE_STRING);
    $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);

    if (!$email) {
        logSecurityEvent($conn, "Invalid email format attempt", $username, $_POST['email']);
        $message = "<p style='color:red;'>Invalid email format!</p>"; // Display error in red
    } else {
        // ✅ Fix: Check if email is already registered
        $checkEmail = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $checkEmail->bind_param("s", $email);
        $checkEmail->execute();
        $result = $checkEmail->get_result();
        if ($result->num_rows > 0) {
            logSecurityEvent($conn, "Duplicate email registration attempt", $username, $email);
            $message = "<p style='color:red;'>Email already in use!</p>"; // Display error in red
        } else {
            // ✅ Fix: Secure password hashing (Fixes A02:2021 - Cryptographic Failures)
            $password = password_hash($_POST['password'], PASSWORD_BCRYPT);

            // ✅ Fix: Prevent users from selecting their own role
            $role = 'user';  // Default role assignment

            // ✅ FIX: Use prepared statements to prevent SQL Injection
            $sql = $conn->prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)");
            $sql->bind_param("ssss", $username, $email, $password, $role);

            if ($sql->execute()) {
                logSecurityEvent($conn, "Successful registration", $username, $email);
                $message = "<p style='color:green;'>Registration successful! <a href='login.php'>Login</a></p>"; // Success message in green
            } else {
                // ✅ Fix: Generic error message to prevent information disclosure
                logSecurityEvent($conn, "Failed registration attempt", $username, $email);
                $message = "<p style='color:red;'>Registration failed. Please try again later.</p>"; // Display error in red
            }
        }
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Banking System</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>Register</h2>

        <?php echo $message; ?>  <!-- Display message dynamically -->

        <form action="register.php" method="post">
            <label>Username:</label>
            <input type="text" name="username" required>

            <label>Email:</label>
            <input type="email" name="email" required>

            <label>Password:</label>
            <input type="password" name="password" required>

            <label>Role:</label>

            <button type="submit">Register</button>
        </form>

        <p>Already have an account? <a href="login.php">Login here</a></p>
    </div>
</body>
</html>
