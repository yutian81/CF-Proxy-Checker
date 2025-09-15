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
function isIPv6($str) {
    return filter_var($str, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}

function simplifyIPv6($ipv6) {
    $addr = inet_pton($ipv6);
    if ($addr === false) return $ipv6;
    return inet_ntop($addr);
}

function extractNAT64Prefix($ipv6Address) {
    $binary_ip = @inet_pton($ipv6Address);
    if ($binary_ip === false) return 'unknown::/96';
    $prefix_binary = substr($binary_ip, 0, 12);
    $prefix_full_binary = $prefix_binary . str_repeat("\0", 4);
    $prefix_ipv6 = inet_ntop($prefix_full_binary);
    return simplifyIPv6($prefix_ipv6) . '/96';
}

function parseCdnCgiTrace($text) {
    $result = [];
    $lines = explode("\n", trim($text));
    foreach ($lines as $line) {
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $result[trim($key)] = trim($value);
        }
    }
    return $result;
}

function fetchCdnCgiTrace($ipv6Address) {
    try {
        $socket = @stream_socket_client("tcp://[{$ipv6Address}]:80", $errno, $errstr, 5);
        if (!$socket) {
            throw new Exception("Socket连接失败: $errstr");
        }
        stream_set_timeout($socket, 5);

        $httpRequest = "GET /cdn-cgi/trace HTTP/1.1\r\n";
        $httpRequest .= "Host: [{$ipv6Address}]\r\n";
        $httpRequest .= "User-Agent: Mozilla/5.0 cmliu/PHP-CheckNAT64\r\n";
        $httpRequest .= "Connection: close\r\n\r\n";

        fwrite($socket, $httpRequest);
        $response = stream_get_contents($socket);
        fclose($socket);

        $headerEndPos = strpos($response, "\r\n\r\n");
        if ($headerEndPos === false) {
            return ['success' => false, 'error' => '无效的HTTP响应'];
        }
        $headers = substr($response, 0, $headerEndPos);
        $body = substr($response, $headerEndPos + 4);

        if (strpos($headers, '200 OK') === false) {
            preg_match('/HTTP\/\d\.\d (\d+)/', $headers, $matches);
            return ['success' => false, 'error' => "HTTP状态码: " . ($matches[1] ?? '未知')];
        }
        return ['success' => true, 'data' => $body];
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

function resolveToIPv6($target, $DNS64Server) {
    $ipv4 = filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? $target : null;
    if (!$ipv4) {
        $records = @dns_get_record($target, DNS_A);
        if (!$records || empty($records)) {
            throw new Exception("未能解析到 {$target} 的IPv4地址");
        }
        $ipv4 = $records[array_rand($records)]['ip'];
    }

    if (substr($DNS64Server, -3) === '/96') {
        $prefix = substr($DNS64Server, 0, -3);
        $prefix_bin = @inet_pton($prefix);
        $ipv4_bin = inet_pton($ipv4);
        if ($prefix_bin === false || $ipv4_bin === false) {
            throw new Exception("无效的IP或前缀格式");
        }
        return inet_ntop(substr($prefix_bin, 0, 12) . $ipv4_bin);
    } else {
        $queryDomain = $ipv4 . base64_decode('LmlwLjA5MDIyNy54eXo=');
        $id = random_int(0, 65535);
        $header = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);
        $qname = '';
        foreach (explode('.', $queryDomain) as $part) {
            $qname .= chr(strlen($part)) . $part;
        }
        $qname .= "\0";
        $question = $qname . pack('nn', 28, 1);
        $packet = $header . $question;
        
        $dns_server_ip = isIPv6($DNS64Server) ? "[{$DNS64Server}]" : $DNS64Server;
        $socket = @stream_socket_client("tcp://{$dns_server_ip}:53", $errno, $errstr, 5);
        if (!$socket) throw new Exception("无法连接到DNS64服务器: $errstr");

        fwrite($socket, pack('n', strlen($packet)) . $packet);
        $response_with_len = fread($socket, 514);
        fclose($socket);

        if (strlen($response_with_len) < 2) throw new Exception("DNS响应过短");

        $response_len = unpack('n', substr($response_with_len, 0, 2))[1];
        $response = substr($response_with_len, 2, $response_len);
        if (strlen($response) < 12) throw new Exception("DNS响应报文不完整");

        $header_data = unpack('n_id/n_flags/n_qdcount/n_ancount', $response);
        if ($header_data['_id'] !== $id || $header_data['_ancount'] < 1) {
            throw new Exception("未在DNS响应中找到答案");
        }

        $offset = 12;
        while (ord($response[$offset]) != 0) { $offset += ord($response[$offset]) + 1; }
        $offset += 5;

        for ($i = 0; $i < $header_data['_ancount']; $i++) {
            if ((ord($response[$offset]) & 0xC0) === 0xC0) {
                $offset += 2;
            } else {
                while (ord($response[$offset]) != 0) $offset += ord($response[$offset]) + 1;
                $offset++;
            }
            $answer_meta = unpack('n_type/n_class/N_ttl/n_rdlength', substr($response, $offset));
            $offset += 10;
            if ($answer_meta['_type'] == 28 && $answer_meta['_rdlength'] == 16) {
                return inet_ntop(substr($response, $offset, 16));
            }
            $offset += $answer_meta['_rdlength'];
        }
        throw new Exception("未在DNS响应中找到AAAA记录");
    }
}
  
// --- 3. 主逻辑 & 路由 ---
$path = strtolower(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

$hostname = $_SERVER['HTTP_HOST'] ?? 'localhost';
$UA = $_SERVER['HTTP_USER_AGENT'] ?? 'null';
$timestamp = ceil(time() / (60 * 60 * 8));
$临时TOKEN = 双重哈希($hostname . $timestamp . $UA);
$临时TOKEN_JS = htmlspecialchars($临时TOKEN);
$永久TOKEN_final = $永久TOKEN ?: $临时TOKEN;

if (preg_match('#/nat64/check#', $path)) {
    header('Content-Type: application/json; charset=UTF-8');
    $查询参数 = $_GET['dns64'] ?? $_GET['nat64'] ?? 'dns64.cmliussss.net';
    $host = $_GET['host'] ?? 'cf.hw.090227.xyz';

    try {
        $ipv6地址 = resolveToIPv6($host, $查询参数);
        $traceResult = fetchCdnCgiTrace($ipv6地址);
        $simplifiedIPv6 = simplifyIPv6($ipv6地址);
        $nat64Prefix = extractNAT64Prefix($simplifiedIPv6);

        if ($traceResult['success']) {
            $result = parseCdnCgiTrace($traceResult['data']);
            $response = [
                'success' => true,
                'nat64_ipv6' => $simplifiedIPv6,
                'nat64_prefix' => $nat64Prefix,
                'cdn_cgi_url' => "http://[{$simplifiedIPv6}]/cdn-cgi/trace",
                'trace_data' => $result,
                'timestamp' => gmdate('Y-m-d\TH:i:s.v\Z')
            ];
            echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => '请求失败', 'message' => $traceResult['error']], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => '解析失败', 'message' => $e->getMessage()], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
    exit;

} elseif (preg_match('#/nat64/ip-info#', $path)) {
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
        // 这里我们使用来自socks5的getIpInfo，因为逻辑相同
        $ch = curl_init("http://ip-api.com/json/" . urlencode(trim($ip, '[]')) . "?lang=zh-CN");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5]);
        $response = curl_exec($ch);
        curl_close($ch);
        $data = json_decode($response, true) ?: ['status' => 'error', 'message' => 'API请求失败'];
        $data['timestamp'] = gmdate('Y-m-d\TH:i:s.v\Z');
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'IP查询失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
    exit;
  
} else {
    // 其他所有 /nat64/... 的请求，都视为页面请求
    if ($永久TOKEN && ($永久TOKEN !== $临时TOKEN)) {
        require_once 'nginx_template.php';
    } elseif ($URL302) {
        header("Location: $URL302", true, 302);
        exit;
    } else {
        require_once 'nat64_template.php';
    }
}

?>
