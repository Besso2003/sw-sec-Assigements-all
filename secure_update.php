<?php
// ✅ Secure software update: Uses HTTPS, verifies integrity, prevents unauthorized execution
$url = "https://trustedsource.com/update.exe"; // Ensure HTTPS is used
$expected_hash = "your_expected_sha256_hash_here"; // Replace with the actual hash

// Download the update securely
$file_data = file_get_contents($url);

if ($file_data === false) {
    die("Error: Could not download update.");
}

// Save the file
$file_path = "update.exe";
file_put_contents($file_path, $file_data);

// Verify file integrity using SHA-256 hash
$downloaded_hash = hash_file("sha256", $file_path);

if ($downloaded_hash !== $expected_hash) {
    unlink($file_path); // Delete the corrupted file
    die("Error: Integrity check failed. Update file is not trusted.");
}

echo "Update downloaded and verified successfully. Manual execution required.";

// ⚠️ DO NOT automatically execute the update
// Instead, require an admin to manually inspect and run the update

?>

<?php
// // ✅ Secure software update: Uses HTTPS, verifies integrity, prevents unauthorized execution
//
// $url = "https://trustedsource.com/update.exe"; // Ensure HTTPS is used
// $expected_hash = "your_expected_sha256_hash_here"; // Replace with the actual hash
// $signature_url = "https://trustedsource.com/update.sig"; // Cryptographic signature (optional)
// $public_key_path = "trusted_public_key.pem"; // Path to the trusted public key (optional)
//
// // 1️⃣ Securely Download the Update Using cURL
// $ch = curl_init($url);
// curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
// curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
// $file_data = curl_exec($ch);
// $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
// curl_close($ch);
//
// if ($http_status !== 200 || $file_data === false) {
//     die("❌ Error: Could not download update.");
// }
//
// // Save the file
// $file_path = "update.exe";
// file_put_contents($file_path, $file_data);
//
// // 2️⃣ Verify File Integrity Using SHA-256 Hash
// $downloaded_hash = hash_file("sha256", $file_path);
// if ($downloaded_hash !== $expected_hash) {
//     unlink($file_path); // Delete the corrupted file
//     die("❌ Error: Integrity check failed. Update file is not trusted.");
// }
//
// // 3️⃣ (Optional) Verify the Update's Digital Signature
// if (file_exists($public_key_path)) {
//     // Download the signature file
//     $sig_ch = curl_init($signature_url);
//     curl_setopt($sig_ch, CURLOPT_RETURNTRANSFER, true);
//     curl_setopt($sig_ch, CURLOPT_SSL_VERIFYPEER, true);
//     $signature = curl_exec($sig_ch);
//     curl_close($sig_ch);
//
//     if ($signature === false) {
//         unlink($file_path);
//         die("❌ Error: Could not download signature file.");
//     }
//
//     // Save the signature file
//     $sig_path = "update.sig";
//     file_put_contents($sig_path, $signature);
//
//     // Verify the signature
//     $public_key = openssl_pkey_get_public(file_get_contents($public_key_path));
//     $verified = openssl_verify($file_data, base64_decode($signature), $public_key, OPENSSL_ALGO_SHA256);
//
//     if ($verified !== 1) {
//         unlink($file_path);
//         unlink($sig_path);
//         die("❌ Error: Signature verification failed. Update is not authentic.");
//     }
//
//     echo "✅ Signature verified successfully! ";
// }
//
// // 4️⃣ Require Manual Execution by an Admin
// echo "✅ Update downloaded and verified successfully. Manual execution required.";
//
// // ⚠️ DO NOT automatically execute the update
// // Instead, an admin should manually inspect and run the update.
// ?>
//
