<?php
$mgmt_api = getenv('MGMT_API_URL') ?: 'http://mgmt:9090';
$api_key = getenv('HONEYPOT_API_KEY') ?: 'hk_live_8f92bd8c734a6eef9012';

function logAttack($type, $data) {
    global $mgmt_api, $api_key;
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $session_id = 'php_lfi_' . md5($ip);
    
    $payload = json_encode([
        'session_id' => $session_id,
        'ip' => $ip,
        'port' => $_SERVER['REMOTE_PORT'] ?? 0,
        'protocol' => 'http-php-lfi',
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

// Path Traversal & LFI
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    if (strpos($page, '../') !== false || strpos($page, 'passwd') !== false || strpos($page, 'http') !== false) {
        logAttack('lfi_attempt', "Payload: $page");
    }
    
    if (file_exists($page)) {
        echo "<pre>" . htmlspecialchars(file_get_contents($page)) . "</pre>";
    } else {
        echo "<b>Warning</b>: file_get_contents(" . htmlspecialchars($page) . "): failed to open stream: No such file or directory in <b>/var/www/html/index.php</b> on line <b>38</b><br />";
    }
} else {
?>
<!DOCTYPE html>
<html>
<head><title>Document Viewer</title></head>
<body>
    <h1>Internal Docs Viewer</h1>
    <a href="?page=about.html">About Us</a>
</body>
</html>
<?php 
} 
?>
