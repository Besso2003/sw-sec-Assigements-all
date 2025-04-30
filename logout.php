<?php
session_start();
session_destroy(); // Destroy session data
header("Location: ../backend/login.php"); // Redirect to login page
exit();
?>
