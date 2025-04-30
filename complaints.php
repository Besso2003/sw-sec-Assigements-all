<?php
session_start();
include 'db.php';


function logSecurityEvent($conn, $event, $user_id = NULL) {
    $stmt = $conn->prepare("INSERT INTO security_logs (user_id, event, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, NOW())");
    if ($stmt) {
        $ip_address = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'];
        $stmt->bind_param("isss", $user_id, $event, $ip_address, $user_agent);
        $stmt->execute();
        $stmt->close();
    } else {
        error_log("Failed to log security event: " . $event);
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
// ❌ No logging for unauthorized access attempts
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'user') {
    logSecurityEvent($conn, "Unauthorized access attempt - User ID: " . ($_SESSION['user_id'] ?? "unknown") . " tried to upload complaints without permission.", $_SESSION['user_id'] ?? NULL);
    die("Unauthorized access! Only users can upload complaints. <a href='login.php'>Login</a>");
}

$message = ""; // ✅ Start with an empty message

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user_id = $_SESSION['user_id'];
    $file_url_mode = isset($_POST['file_url']) && filter_var($_POST['file_url'], FILTER_VALIDATE_URL);
    $file = $file_url_mode ? null : ($_FILES['complaint_file'] ?? null);

    if ($file_url_mode) {
        $url = $_POST['file_url'];

        // Validate and block internal cloud metadata services (e.g., AWS metadata URL)
        $parsed_url = parse_url($url);

        // Block access to internal resources (including AWS metadata service and localhost)
        $blocked_hosts = ['localhost', '127.0.0.1', '169.254.169.254'];  // List of blocked internal hosts (e.g., AWS metadata)
        if (in_array($parsed_url['host'], $blocked_hosts)) {
            logSecurityEvent($conn, "Blocked SSRF attempt - Access to internal resource: $url", $user_id);
            die("Invalid URL. Access to internal resources is not allowed.");
        }

        // Attempt to fetch the file content
        $file_contents = @file_get_contents($url);

        if ($file_contents !== false) {
            $upload_dir = "uploads/";
            $safe_file_name = time() . "_remote_file";
            $file_path = $upload_dir . $safe_file_name;

            file_put_contents($file_path, $file_contents);

            $stmt = $conn->prepare("INSERT INTO complaints (user_id, file_path, date) VALUES (?, ?, NOW())");
            $stmt->bind_param("is", $user_id, $file_path);
            if ($stmt->execute()) {
                logSecurityEvent($conn, "Complaint file fetched from URL: $url", $user_id);
                $message = "Complaint file fetched and saved from URL!";
            } else {
                $message = "Database error.";
            }
            $stmt->close();
        } else {
            $message = "Failed to fetch file from URL.";
        }
    }
}



// if ($_SERVER["REQUEST_METHOD"] == "POST") {
//     $user_id = $_SESSION['user_id'];
//
//     // Check if 'complaint_file' is present in $_FILES
//     if (isset($_FILES['complaint_file']) && $_FILES['complaint_file']['error'] === UPLOAD_ERR_OK) {
//         $file = $_FILES['complaint_file'];
//
//         // Log file upload attempt
//         logSecurityEvent($conn, "User ID: $user_id is uploading a complaint file.", $user_id);
//
//         // Validate file type
//         $allowed_types = ['image/jpeg', 'image/png', 'application/pdf'];
//         if (!in_array($file['type'], $allowed_types)) {
//             logSecurityEvent($conn, "Invalid file type upload attempt - User ID: $user_id, File Type: " . $file['type'], $user_id);
//             $message = "Invalid file type. Only JPG, PNG, and PDF files are allowed.";
//         } else {
//             // Check the size of the uploaded file
//             $max_file_size = 41943040; // 40MB in bytes
//             if ($file['size'] > $max_file_size) {
//                 logSecurityEvent($conn, "File size exceeds limit - User ID: $user_id, File Size: " . $file['size'], $user_id);
//                 $message = "File size exceeds the limit. Maximum allowed size is 40MB.";
//             } else {
//                 // Securely sanitize and save file
//                 $upload_dir = "uploads/";
//                 $safe_file_name = preg_replace("/[^a-zA-Z0-9\._-]/", "_", basename($file["name"]));
//                 $safe_file_name = time() . "_" . $safe_file_name; // Add timestamp to avoid name collisions
//                 $file_path = $upload_dir . $safe_file_name;
//
//                 if (move_uploaded_file($file["tmp_name"], $file_path)) {
//                     $stmt = $conn->prepare("INSERT INTO complaints (user_id, file_path, date) VALUES (?, ?, NOW())");
//                     $stmt->bind_param("is", $user_id, $file_path);
//
//                     if ($stmt->execute()) {
//                         logSecurityEvent($conn, "Complaint uploaded successfully - User ID: $user_id, File: $safe_file_name", $user_id);
//                         $message = "Complaint uploaded successfully!";
//                     } else {
//                         logSecurityEvent($conn, "Database error: Failed to save complaint - User ID: $user_id, Error: " . $stmt->error, $user_id);
//                         $message = "Database error: Could not save complaint.";
//                     }
//                     $stmt->close();
//                 } else {
//                     logSecurityEvent($conn, "File move error - User ID: $user_id, File: $safe_file_name", $user_id);
//                     $message = "Error moving uploaded file.";
//                 }
//             }
//         }
//     } else {
//         // Handle file upload error
//         logSecurityEvent($conn, "File upload error - User ID: $user_id, Error Code: " . ($_FILES['complaint_file']['error'] ?? 'unknown'), $user_id);
//         $message = "Error uploading file. Please try again.";
//     }
// }

// if ($_SERVER["REQUEST_METHOD"] == "POST") {
//     $user_id = $_SESSION['user_id'];
//     $file_url_mode = isset($_POST['file_url']) && filter_var($_POST['file_url'], FILTER_VALIDATE_URL);
//     $file = $file_url_mode ? null : ($_FILES['complaint_file'] ?? null);
//
// //     $file = $_FILES['complaint_file'];
//
//     if ($file_url_mode) {
//         // URL handling code remains the same
//         $url = $_POST['file_url'];
//         $file_contents = @file_get_contents($url);
//
//         if ($file_contents !== false) {
//             $upload_dir = "uploads/";
//             $safe_file_name = time() . "_remote_file";
//             $file_path = $upload_dir . $safe_file_name;
//
//             file_put_contents($file_path, $file_contents);
//
//             $stmt = $conn->prepare("INSERT INTO complaints (user_id, file_path, date) VALUES (?, ?, NOW())");
//             $stmt->bind_param("is", $user_id, $file_path);
//             if ($stmt->execute()) {
//                 logSecurityEvent($conn, "Complaint file fetched from URL: $url", $user_id);
//                 $message = "Complaint file fetched and saved from URL!";
//             } else {
//                 $message = "Database error.";
//             }
//             $stmt->close();
//         } else {
//             $message = "Failed to fetch file from URL.";
//         }
//     } else {
//         if (isset($file) && $file !== null && $file['error'] !== UPLOAD_ERR_OK) {
//             logSecurityEvent($conn, "File upload error - User ID: $user_id, Error Code: " . ($file['error'] ?? 'missing'), $user_id);
//             $message = "Error uploading file.";
//         } else {
//             if (!isset($file['error'])) {
//                 logSecurityEvent($conn, "File upload error: No error code returned - User ID: $user_id", $user_id);
//                 $message = "File upload failed. Please try again.";
//             } else {
//                 // ✅ Validate file type
//                 $allowed_types = ['image/jpeg', 'image/png', 'application/pdf'];
//                 if (!in_array($file['type'], $allowed_types)) {
//                     logSecurityEvent($conn, "Invalid file type upload attempt - User ID: $user_id, File Type: " . $file['type'], $user_id);
//                     $message = "Invalid file type. Only JPG, PNG, and PDF files are allowed.";
//                 } else {
//                     // ✅ Securely sanitize and save file
//                     $upload_dir = "uploads/";
//                     $safe_file_name = preg_replace("/[^a-zA-Z0-9\._-]/", "_", basename($file["name"]));
//                     $safe_file_name = time() . "_" . $safe_file_name; // ✅ Add timestamp to avoid name collisions
//                     $file_path = $upload_dir . $safe_file_name;
//
//                     // ✅ Securely move the file
//                     if (move_uploaded_file($file["tmp_name"], $file_path)) {
//                         // ✅ Use prepared statements
//                         $stmt = $conn->prepare("INSERT INTO complaints (user_id, file_path, date) VALUES (?, ?, NOW())");
//                         $stmt->bind_param("is", $user_id, $file_path);
//
//                         if ($stmt->execute()) {
//                             logSecurityEvent($conn, "Complaint uploaded successfully - User ID: $user_id, File: $safe_file_name", $user_id);
//                             $message = "Complaint uploaded successfully!";
//                         } else {
//                             logSecurityEvent($conn, "Database error: Failed to save complaint - User ID: $user_id, Error: " . $stmt->error, $user_id);
//                             error_log("Database error: Could not save complaint for user ID: $user_id. Error: " . $stmt->error);
//                             $message = "Database error: Could not save complaint.";
//                         }
//                         $stmt->close();
//                     } else {
//                         logSecurityEvent($conn, "File move error - User ID: $user_id, File: $safe_file_name", $user_id);
//                         $message = "Error moving uploaded file.";
//                     }
//                 }
//             }
//         }
//     }
// }
//
//     // ❌ SSRF-prone feature: Fetch file from external URL if provided
// if (isset($_POST['file_url']) && filter_var($_POST['file_url'], FILTER_VALIDATE_URL)) {
//     $url = $_POST['file_url'];
//     $file_contents = @file_get_contents($url);
//
//     if ($file_contents !== false) {
//         $upload_dir = "uploads/";
//         $safe_file_name = time() . "_remote_file";
//         $file_path = $upload_dir . $safe_file_name;
//
//         file_put_contents($file_path, $file_contents);
//
//         $stmt = $conn->prepare("INSERT INTO complaints (user_id, file_path, date) VALUES (?, ?, NOW())");
//         $stmt->bind_param("is", $user_id, $file_path);
//         if ($stmt->execute()) {
//             logSecurityEvent($conn, "Complaint file fetched from URL: $url", $user_id);
//             $message = "Complaint file fetched and saved from URL!";
//         } else {
//             $message = "Database error.";
//         }
//         $stmt->close();
//     } else {
//         $message = "Failed to fetch file from URL.";
//     }
// }
//
//
//     // ✅ Log file upload attempts with specific errors
//     if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
//         logSecurityEvent($conn, "File upload error - User ID: $user_id, Error Code: " . $file['error'], $user_id);
//         $message = "Error uploading file.";
//     } else {
//         // ✅ Validate file type
//         $allowed_types = ['image/jpeg', 'image/png', 'application/pdf'];
//         if (!in_array($file['type'], $allowed_types)) {
//             logSecurityEvent($conn, "Invalid file type upload attempt - User ID: $user_id, File Type: " . $file['type'], $user_id);
//             $message = "Invalid file type. Only JPG, PNG, and PDF files are allowed.";
//         } else {
//             // ✅ Securely sanitize and save file
//             $upload_dir = "uploads/";
//             $safe_file_name = preg_replace("/[^a-zA-Z0-9\._-]/", "_", basename($file["name"]));
//             $safe_file_name = time() . "_" . $safe_file_name; // ✅ Add timestamp to avoid name collisions
//             $file_path = $upload_dir . $safe_file_name;
//
//             // ✅ Securely move the file
//             if (move_uploaded_file($file["tmp_name"], $file_path)) {
//                 // ✅ Use prepared statements
//                 $stmt = $conn->prepare("INSERT INTO complaints (user_id, file_path, date) VALUES (?, ?, NOW())");
//                 $stmt->bind_param("is", $user_id, $file_path);
//
//                 if ($stmt->execute()) {
//                     logSecurityEvent($conn, "Complaint uploaded successfully - User ID: $user_id, File: $safe_file_name", $user_id);
//                     $message = "Complaint uploaded successfully!";
//                 } else {
//                     logSecurityEvent($conn, "Database error: Failed to save complaint - User ID: $user_id, Error: " . $stmt->error, $user_id);
//                     error_log("Database error: Could not save complaint for user ID: $user_id. Error: " . $stmt->error);
//                     $message = "Database error: Could not save complaint.";
//                 }
//                 $stmt->close();
//             } else {
//                 logSecurityEvent($conn, "File move error - User ID: $user_id, File: $safe_file_name", $user_id);
//                 $message = "Error moving uploaded file.";
//             }
//         }
//     }
// }


//     if (move_uploaded_file($file["tmp_name"], $file_path)) {
//         $conn->query("INSERT INTO complaints (user_id, file_path, date) VALUES ('$user_id', '$file_path', NOW())");
//
//          // Log the complaint upload action
//          // (A02:2021 – Cryptographic Failures)
//          // (A09:2021 – Security Logging and Monitoring Failures)
//          // ❌ Security Misconfiguration: Logging file name without sanitization (Potential data exposure)
//          $conn->query("INSERT INTO logs (user_id, action, timestamp)
//                          VALUES ('$user_id', 'Uploaded complaint file: $file_path', NOW())");
//
//         $message = "Complaint uploaded successfully!";
//     } else {
//         $message = "Error uploading file.";
//     }

// Fetch complaints for the logged-in user
// $user_id = $_SESSION['user_id'];
// $complaints = $conn->query("SELECT * FROM complaints WHERE user_id = '$user_id' ORDER BY date DESC");

// ✅ Secure query to fetch complaints
$user_id = $_SESSION['user_id'];
$complaints = $conn->prepare("SELECT * FROM complaints WHERE user_id = ? ORDER BY date DESC");
$complaints->bind_param("i", $user_id);
$complaints->execute();
$result = $complaints->get_result();

// ✅ Log access to the user dashboard
logSecurityEvent($conn, "User Successfully viewed complaint page", $user_id);

?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Complaint</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>Upload Complaint</h2>

        <!-- Display success or error message -->
        <?php if ($message): ?>
            <p style="color: <?= strpos($message, 'successfully') !== false ? 'green' : 'red'; ?>;">
                <?= htmlspecialchars($message); ?>
            </p>
        <?php endif; ?>

        <!-- Form to Upload Complaint File from URL -->
        <form method="POST">
            <label for="file_url">Enter File URL:</label>
            <input type="url" name="file_url" placeholder="Enter URL to fetch file from" required>

            <button type="submit">Submit Complaint</button>
        </form>

        <!-- Display Complaints -->
        <h2>My Complaints</h2>
        <table border="1">
            <tr>
                <th>Complaint File</th>
                <th>Date</th>
            </tr>
            <?php while ($complaint = $result->fetch_assoc()) : ?>
                <tr>
                    <td><a href="<?= htmlspecialchars($complaint['file_path']); ?>">View File</a></td>
                    <td><?= htmlspecialchars($complaint['date']); ?></td>
                </tr>
            <?php endwhile; ?>
        </table>

        <a href="user_dashboard.php">Back to Dashboard</a>
    </div>
</body>
</html>

