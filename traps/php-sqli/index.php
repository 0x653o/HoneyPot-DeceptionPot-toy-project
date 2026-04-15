<?php
$mgmt_api = getenv('MGMT_API_URL') ?: 'http://mgmt:9090';
$api_key = getenv('HONEYPOT_API_KEY') ?: 'hk_live_8f92bd8c734a6eef9012';

function logAttack($type, $data) {
    global $mgmt_api, $api_key;
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $session_id = 'php_sqli_' . md5($ip);
    
    $payload = json_encode([
        'session_id' => $session_id,
        'ip' => $ip,
        'port' => $_SERVER['REMOTE_PORT'] ?? 0,
        'protocol' => 'http-php-sqli',
        'event_type' => $type,
        'data' => $data
    ]);

    $ch = curl_init("$mgmt_api/api/internal/ingest/event");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        "X-API-Key: $api_key"
    ]);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_TIMEOUT, 2);
    curl_exec($ch);
    curl_close($ch);
}

// Health check endpoint
if ($_SERVER['REQUEST_URI'] === '/health') {
    http_response_code(200);
    echo "OK";
    exit;
}

// SQL Injection (SQLi)
if (isset($_POST['username']) && isset($_POST['password'])) {
    // Generate new memory database tailored to request
    $db = new PDO('sqlite::memory:');
    $db->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
    $db->exec("INSERT INTO users (username, password) VALUES ('admin', 'supersecure123')");
    $db->exec("INSERT INTO users (username, password) VALUES ('user', 'password123')");
    
    $user = $_POST['username'];
    $pass = $_POST['password'];

    logAttack('sqli_attempt', "User: $user | Pass: $pass");
    
    try {
        $stmt = $db->query("SELECT * FROM users WHERE username = '$user' AND password = '$pass'");
        
        if ($stmt && $result = $stmt->fetch()) {
             echo "<h1>Login Success! Welcome " . htmlspecialchars($result['username'] ?? 'admin') . ".</h1>";
             logAttack('sqli_success', "Bypassed with User: $user");
        } else {
             echo "<h1>Login Failed: Invalid credentials.</h1>";
        }
    } catch (Exception $e) {
        logAttack('sqli_error', "Error: " . $e->getMessage());
        echo "<b>Fatal error</b>: Uncaught PDOException: " . $e->getMessage() . " in /var/www/html/index.php<br />";
    }
} else {
?>
<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
    <h3>SQLi Login Portal</h3>
    <form method="POST">
        Username: <input type="text" name="username" size="30"><br>
        Password: <input type="password" name="password" size="30"><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
<?php 
} 
?>
