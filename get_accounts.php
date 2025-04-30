<?php
include 'db.php';
session_start();

$result = $conn->query("SELECT * FROM accounts WHERE user_id = $_SESSION[user_id]");
echo json_encode($result->fetch_all(MYSQLI_ASSOC));
?>
