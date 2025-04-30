<?php
// ⚠️ Insecure software update: No validation, no authentication, no integrity check
$url = "http://example.com/update.exe"; // Uses HTTP (not HTTPS)
$file_data = file_get_contents($url); // No verification of source authenticity

if ($file_data === false) {
    die("Error: Could not download update.");
}

file_put_contents("update.exe", $file_data); // Stores the unverified file

exec("update.exe"); // ⚠️ Directly executes an untrusted file
?>
