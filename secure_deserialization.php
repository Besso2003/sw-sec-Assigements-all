<?php
// ✅ Secure Deserialization: Prevents arbitrary code execution

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = $_POST['payload']; // User input

    // Use JSON instead of PHP serialization to prevent object injection
    $decoded_data = json_decode($data, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        die("Error: Invalid data format.");
    }

    echo "Data received and safely processed!";
} else {
    echo "Send a POST request with JSON data.";
}
?>
