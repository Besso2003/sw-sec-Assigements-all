<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo "Unauthorized access!";
    exit();
}

// Proceed with fetching and displaying protected data
echo "Sensitive Data: You are authorized to view this!";
?>
