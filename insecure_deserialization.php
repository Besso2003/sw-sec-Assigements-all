<?php
// ⚠️ Insecure Deserialization - Accepts user input and unserializes it without validation

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = $_POST['payload']; // Attacker-controlled input
    $object = unserialize($data); // ⚠️ Unsecure: Can execute arbitrary code

    echo "Object unserialized successfully!";
} else {
    echo "Send a POST request with serialized data.";
}
?>
