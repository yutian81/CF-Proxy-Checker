<?php
// PHP 版本：建议 7.4 或更高
// 依赖扩展：curl, sockets (通常默认启用)
ini_set('display_errors', 0);
error_reporting(0);
require_once 'config.php';
require_once 'functions.php';

// --- 1. 读取和配置环境变量 ---
$网站图标 = defined('ICO') && ICO ? ICO : 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
$网站图标_HTML = htmlspecialchars($网站图标, ENT_QUOTES);
$HEAD_FONTS_HTML = defined('HEAD_FONTS') ? HEAD_FONTS : '';
$BEIAN_HTML = defined('BEIAN') && BEIAN ? BEIAN : '© 2025 CF反代检测工具集 By cmliu | Yutian81';
$永久TOKEN = defined('TOKEN') && TOKEN ? TOKEN : null;
$URL302 = defined('URL302') ? URL302 : null;
// 随机背景图，须在config.php中将IMG变量设为图片数组
$IMG_CSS = 'background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);';
if (defined('IMG') && IMG) {
    $imgs = 整理(IMG);
    if (!empty($imgs)) {
        $img_url = $imgs[array_rand($imgs)];
        $IMG_CSS = 'background-image: url("' . htmlspecialchars($img_url, ENT_QUOTES, 'UTF-8') . '");';
    }
}

// --- 2. 核心工具函数 ---
function socks5AddressParser($address) {
    // 预处理，去除协议前缀
    if (strpos($address, '://') !== false) {
        $address = substr($address, strpos($address, '://') + 3);
    }

    // 认证@主机
    $lastAtIndex = strrpos($address, "@");
    $hostPart = ($lastAtIndex === false) ? $address : substr($address, $lastAtIndex + 1);
    $authPart = ($lastAtIndex === false) ? null : substr($address, 0, $lastAtIndex);
    
    $username = $password = null;
    if ($authPart) {
        // 使用 limit=2 来确保密码中的 ':' 不会影响解析
        $auth_parts = explode(":", $authPart, 2);
        if (count($auth_parts) !== 2) {
            throw new Exception('无效的代理地址格式：认证部分必须是 "username:password" 的形式');
        }
        list($username, $password) = $auth_parts;
    }

    $hostname = '';
    $port = 0;

    // 优化主机和端口的解析，能正确处理IPv6
    if (preg_match('/^(\[.+\]):(\d+)$/', $hostPart, $matches)) {
        // 匹配 IPv6 地址: [ipv6]:port
        $hostname = $matches[1];
        $port = (int)$matches[2];
    } else {
        // 匹配 IPv4 或域名
        $lastColon = strrpos($hostPart, ':');
        if ($lastColon === false) {
            // 没有端口，根据协议使用默认端口
            $hostname = $hostPart;
            // 因为我们无法在这里知道协议，所以让调用者决定默认端口
            // 但为了兼容性，我们可以暂时不设，依赖于外部逻辑
        } else {
            $hostname = substr($hostPart, 0, $lastColon);
            $port = (int)substr($hostPart, $lastColon + 1);
        }
    }
    
    if (empty($hostname)) {
       throw new Exception('无效的代理地址格式：主机名不能为空');
    }
    if ($port === 0) { // 如果解析后端口为0，说明格式可能有问题
        throw new Exception('无效的代理地址格式：端口号不正确');
    }
    
    $hostname = trim($hostname, '[]');

    return [
        'username' => $username,
        'password' => $password,
        'hostname' => $hostname,
        'port' => $port,
    ];
}

function socks5Connect($proxy, $targetHost, $targetPort) {
    // 为IPv6地址加上方括号
    $connect_host = filter_var($proxy['hostname'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[{$proxy['hostname']}]" : $proxy['hostname'];
    $socket = @stream_socket_client("tcp://{$connect_host}:{$proxy['port']}", $errno, $errstr, 5);
    if (!$socket) throw new Exception("无法连接到SOCKS5代理服务器: $errstr");
    stream_set_timeout($socket, 5);

    $greeting = pack('C3', 0x05, 0x02, 0x00) . pack('C', 0x02);
    if (fwrite($socket, $greeting) === false) throw new Exception("发送SOCKS5问候失败");

    $response = fread($socket, 2);
    if (strlen($response) < 2) throw new Exception("读取SOCKS5服务器响应失败");
    $res_parts = unpack('Cversion/Cmethod', $response);
    if ($res_parts['version'] !== 0x05) throw new Exception("SOCKS5服务器版本错误");

    if ($res_parts['method'] === 0x02) {
        if (!$proxy['username']) throw new Exception("SOCKS5服务器需要认证，但未提供用户名");
        $auth_req = pack('C2', 0x01, strlen($proxy['username'])) . $proxy['username'] . pack('C', strlen($proxy['password'])) . $proxy['password'];
        if (fwrite($socket, $auth_req) === false) throw new Exception("发送SOCKS5认证请求失败");
        $auth_resp = fread($socket, 2);
        if (strlen($auth_resp) < 2 || $auth_resp !== pack('C2', 0x01, 0x00)) {
            throw new Exception("SOCKS5认证失败");
        }
    } elseif ($res_parts['method'] !== 0x00) {
        throw new Exception("SOCKS5服务器不支持所选的认证方法");
    }

    $atyp = 0x03; // Domain name
    $cmd = pack('C4', 0x05, 0x01, 0x00, $atyp) . pack('C', strlen($targetHost)) . $targetHost . pack('n', $targetPort);
    if (fwrite($socket, $cmd) === false) throw new Exception("发送SOCKS5连接请求失败");

    $response = fread($socket, 10);
    if (strlen($response) < 4) throw new Exception("读取SOCKS5连接响应失败");
    $res_parts = unpack('Cversion/Cstatus/Creserved/Catyp', $response);
    if ($res_parts['status'] !== 0x00) throw new Exception("SOCKS5连接目标失败，状态码: " . $res_parts['status']);
    
    return $socket;
}

function httpConnect($proxy, $targetHost, $targetPort) {
    $connect_host = filter_var($proxy['hostname'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[{$proxy['hostname']}]" : $proxy['hostname'];
    $socket = @stream_socket_client("tcp://{$connect_host}:{$proxy['port']}", $errno, $errstr, 5);
    if (!$socket) throw new Exception("无法连接到HTTP代理服务器: $errstr");
    stream_set_timeout($socket, 5);

    $connectRequest = "CONNECT {$targetHost}:{$targetPort} HTTP/1.1\r\n";
    $connectRequest .= "Host: {$targetHost}:{$targetPort}\r\n";
    if ($proxy['username']) {
        $auth = base64_encode($proxy['username'] . ':' . ($proxy['password'] ?? ''));
        $connectRequest .= "Proxy-Authorization: Basic {$auth}\r\n";
    }
    $connectRequest .= "User-Agent: Mozilla/5.0\r\n";
    $connectRequest .= "Proxy-Connection: Keep-Alive\r\n\r\n";
    
    if (fwrite($socket, $connectRequest) === false) throw new Exception("发送HTTP CONNECT请求失败");
    
    $response = '';
    $startTime = time();
    while (strpos($response, "\r\n\r\n") === false) {
        if (time() - $startTime > 5) throw new Exception("读取HTTP代理响应超时");
        $chunk = fread($socket, 1024);
        if ($chunk === false) break;
        $response .= $chunk;
    }
    
    if (stripos($response, "200 Connection established") === false && stripos($response, "200 OK") === false) {
        $first_line = substr($response, 0, strpos($response, "\r\n"));
        throw new Exception("HTTP代理连接失败: " . ($first_line ?: '未知错误'));
    }
    return $socket;
}

function checkProxy($socket, $targetHost, $targetPath) {
    if (!is_resource($socket)) throw new Exception("无效的Socket资源");
    $httpRequest = "GET {$targetPath} HTTP/1.1\r\nHost: {$targetHost}\r\nConnection: close\r\n\r\n";
    if (fwrite($socket, $httpRequest) === false) throw new Exception("通过代理发送HTTP请求失败");
    
    $response = stream_get_contents($socket);
    fclose($socket);
    
    if (preg_match('/ip=([^\s]+)/', $response, $matches)) {
        return $matches[1];
    }
    throw new Exception("无法从代理响应中获取出口IP");
}

function getIpInfo($ip) {
    $finalIp = $ip;
    $allIps = null;
    $isDomain = !filter_var($ip, FILTER_VALIDATE_IP);
    
    if ($isDomain) {
        $records = @dns_get_record($ip, DNS_A | DNS_AAAA);
        if ($records === false || empty($records)) {
            throw new Exception("无法解析域名 {$ip} 的 IP 地址");
        }
        $allIps = array_map(function($r) { return $r['type'] === 'AAAA' ? $r['ipv6'] : $r['ip']; }, $records);
        $finalIp = $allIps[array_rand($allIps)];
    }
    
    $ch = curl_init("https://api.ipapi.is/?q=" . urlencode($finalIp));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $response = curl_exec($ch);
    curl_close($ch);
    
    $data = json_decode($response, true);
    if (!$data) {
        throw new Exception("查询IP信息失败 (无效的JSON响应)");
    }
    
    $data['timestamp'] = gmdate('Y-m-d\TH:i:s.v\Z');
    
    if ($isDomain) {
        $data['domain'] = $ip;
        $data['resolved_ip'] = $finalIp;
        $data['ips'] = $allIps;
    }
    
    return $data;
}

// --- 3. 主逻辑 & 路由 ---
$path = strtolower(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

// --- Token Generation ---
$hostname = $_SERVER['HTTP_HOST'] ?? 'localhost';
$UA = $_SERVER['HTTP_USER_AGENT'] ?? 'null';
$timestamp = ceil(time() / (60 * 60 * 12));
$临时TOKEN = 双重哈希($hostname . $timestamp . $UA);
$临时TOKEN_JS = htmlspecialchars($临时TOKEN);
$永久TOKEN_final = $永久TOKEN ?: $临时TOKEN;

// --- 路由选择 ---
if (preg_match('#/socks5/check#', $path)) {
    // API: /socks5/check
    header('Content-Type: application/json; charset=UTF-8');
    $proxyParam = $_GET['proxy'] ?? $_GET['socks5'] ?? $_GET['http'] ?? null;
    if (!$proxyParam) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => '请提供有效的代理参数：socks5、http 或 proxy'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit();
    }
    $isSocks = stripos($proxyParam, 'socks5://') !== false || isset($_GET['socks5']);
    try {
        $parsedProxy = socks5AddressParser($proxyParam);
        $targetHost = 'check.socks5.090227.xyz';
        $targetPort = 80;
        $targetPath = '/cdn-cgi/trace';
        if ($isSocks) {
            $socket = socks5Connect($parsedProxy, $targetHost, $targetPort);
        } else {
            $socket = httpConnect($parsedProxy, $targetHost, $targetPort);
        }
        $egressIp = checkProxy($socket, $targetHost, $targetPath);
        $ipInfo = getIpInfo($egressIp);
        echo json_encode(array_merge(['success' => true, 'proxy' => $proxyParam], $ipInfo), JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage(), 'proxy' => $proxyParam], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
    exit;

} elseif (preg_match('#/socks5/ip-info#', $path)) {
    // API: /socks5/ip-info
    header('Content-Type: application/json; charset=UTF-8');
    $token = $_GET['token'] ?? null;
    if (!$token || ($token !== $临时TOKEN && $token !== $永久TOKEN_final)) {
         http_response_code(403);
         echo json_encode(['status' => 'error', 'message' => 'IP查询失败: 无效的TOKEN'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
         exit();
    }
    $ip = $_GET['ip'] ?? $_SERVER['REMOTE_ADDR'];
    if (!$ip) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'IP参数未提供'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit();
    }
    try {
        $data = getIpInfo($ip);
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'IP查询失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
    exit;

} else {
    // 其他所有 /socks5/... 的请求，都视为页面请求
    if ($永久TOKEN && ($永久TOKEN !== $临时TOKEN)) {
        require_once 'nginx_template.php';
    } elseif ($URL302) {
        header("Location: $URL302", true, 302);
        exit;
    } else {
        require_once 'socks5_template.php';
    }
}

?>
