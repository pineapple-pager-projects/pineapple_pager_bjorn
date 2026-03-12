<?php
// PHP handles any HTTP method — allows method-tamper bypass of .htaccess <Limit>
echo "<!DOCTYPE html><html><head><title>Admin Panel</title></head><body>";
echo "<h1>Admin Login</h1>";
echo "<form action='/admin/login' method='POST'>";
echo "<label>Username: <input type='text' name='username'></label><br>";
echo "<label>Password: <input type='password' name='password'></label><br>";
echo "<button type='submit'>Login</button>";
echo "</form></body></html>";
?>
