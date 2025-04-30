<?php
$host = 'localhost';
$dbName = 'bank';
$dbUser = 'root';
$dbPass = '';

$conn = new mysqli($host, $dbUser, $dbPass, $dbName);
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}
?>
