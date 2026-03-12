<?php
// Set cookies without Secure or HttpOnly flags
setcookie("session_id", "abc123def456", time() + 3600, "/");
setcookie("user_pref", "default", time() + 3600, "/");
setcookie("auth_token", "tokenvalue789", time() + 3600, "/");
echo "<html><body>";
echo "<h1>Cookies Set</h1>";
echo "<p>Insecure cookies have been set without Secure or HttpOnly flags.</p>";
echo "</body></html>";
?>
