<?php
// PHP 版本：建议 7.4 或更高
// 依赖扩展：curl, sockets (通常默认启用)
require_once 'config.php';

// --- 1. 配置 & 环境变量读取 ---
$网站图标 = defined('ICO') && ICO ? ICO : 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
$永久TOKEN = defined('TOKEN') && TOKEN ? TOKEN : null;
$URL302 = defined('URL302') ? URL302 : null;
$URL = defined('URL') ? URL : null;
$BEIAN = defined('BEIAN') && BEIAN ? BEIAN : '© 2025 Socks5/HTTP Check';
$IMG = defined('IMG') ? IMG : null;


// --- 2. 核心工具函数 ---

function 双重哈希($文本) {
    return strtolower(md5(substr(md5($文本), 7, 20)));
}

function 整理($内容) {
    $替换后的内容 = preg_replace('/[ \t|"\'\r\n]+/', ',', $内容);
    $替换后的内容 = preg_replace('/,+/', ',', $替换后的内容);
    $替换后的内容 = trim($替换后的内容, ',');
    return array_filter(explode(',', $替换后的内容));
}

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

function nginx() {
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!DOCTYPE html>
<html>
      <head>
          <title>Welcome to nginx!</title>
          <style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style>
      </head>
      <body>
          <h1>Welcome to nginx!</h1>
          <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
          <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>
          .<br/>Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
          <p><em>Thank you for using nginx.</em></p>
      </body>
</html>';
}

function HTML($网站图标, $BEIAN, $img, $临时TOKEN) {
    $网站图标_html = $网站图标 ? '<link rel="icon" href="' . htmlspecialchars($网站图标) . '" type="image/x-icon">' : '';
    $img_style = $img ? "background-image: url('" . htmlspecialchars($img) . "');" : "";
    $网络备案_html = $BEIAN;
    $临时TOKEN_JS = htmlspecialchars($临时TOKEN);

    header('Content-Type: text/html; charset=UTF-8');
    echo <<<HTML
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Socks5/HTTP - 代理检测工具</title>
    {$网站图标_html}
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
    :root {
      --primary-color: #3498db; --primary-dark: #2980b9; --secondary-color: #1abc9c;
      --success-color: #2ecc71; --warning-color: #f39c12; --error-color: #e74c3c;
      --bg-primary: #ffffff; --bg-secondary: #f8f9fa; --text-primary: #2c3e50;
      --text-secondary: #6c757d; --border-color: #dee2e6; --shadow-lg: 0 10px 25px rgba(0,0,0,0.15);
      --border-radius: 12px; --border-radius-sm: 8px; --transition: all 0.3s ease;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', sans-serif; line-height: 1.6; color: var(--text-primary);
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      {$img_style}
      background-size: cover; background-position: center; background-attachment: fixed;
      min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
    }
    .container {
      max-width: 1000px; width: 100%; margin: 0 auto;
      background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(10px);
      border-radius: var(--border-radius); box-shadow: var(--shadow-lg);
      border: 1px solid rgba(255, 255, 255, 0.2); overflow: hidden;
    }
    .header {
      padding: 32px;
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px;
      position: relative;
    }
    .header::before {
      content: ""; position: absolute; top: 0; left: 0; right: 0;
      height: 4px; background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
    }
    .header-content h1 { font-size: 2rem; margin-bottom: 4px; color: var(--text-primary); }
    .header-content p { color: var(--text-secondary); }
    .header-input { display: flex; gap: 10px; flex-grow: 1; max-width: 500px; }
    .header-input input {
        flex-grow: 1; padding: 12px 16px; border: 2px solid var(--border-color);
        border-radius: var(--border-radius-sm); font-size: 16px; transition: var(--transition);
    }
    .header-input input:focus {
        outline: none; border-color: var(--primary-color);
        box-shadow: 0 0 0 4px rgba(52, 152, 219, 0.1);
    }
    .header-input button {
        padding: 12px 24px; border: none; border-radius: var(--border-radius-sm); font-size: 16px;
        font-weight: 600; cursor: pointer; transition: var(--transition); color: white;
        background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .header-input button:hover { transform: translateY(-2px); box-shadow: 0 8px 15px rgba(52, 152, 219, 0.2); }
    .header-input button:disabled { background: #adb5bd; cursor: not-allowed; transform: none; box-shadow: none; }
    .results-section {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
        padding: 0 32px 0px 32px;
    }
    .info-card {
        background: var(--bg-secondary);
        padding: 24px;
        border-radius: var(--border-radius-sm);
        border: 1px solid var(--border-color);
        box-shadow: var(--shadow-sm);
    }
    .info-card h3 {
        font-size: 1.5rem;
        margin-bottom: 20px;
        color: var(--text-primary);
        border-bottom: 2px solid var(--primary-color);
        padding-bottom: 10px;
    }
    .info-content .waiting, .info-content .loading, .info-content .error {
        text-align: center;
        color: var(--text-secondary);
        padding: 40px 0;
    }
    .info-content .error { color: var(--error-color); }
    .spinner {
        border: 4px solid #f3f3f3; border-top: 4px solid var(--primary-color); border-radius: 50%;
        width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 0 auto 10px;
    }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    .info-item {
        display: flex; justify-content: space-between; align-items: center;
        padding: 12px 0; border-bottom: 1px solid #e9ecef;
    }
    .info-item:last-child { border-bottom: none; }
    .info-label { font-weight: 500; color: var(--text-secondary); }
    .info-value { font-weight: 600; color: var(--text-primary); text-align: right; }
    .status-yes, .status-no {
        padding: 3px 8px; border-radius: 12px; font-size: 0.8em;
        color: white; font-weight: 600;
    }
    .status-yes { background-color: var(--error-color); }
    .status-no { background-color: var(--success-color); }
    .ip-selector { display: flex; align-items: center; justify-content: flex-end; gap: 8px; }
    .more-ip-btn {
        background: #e9ecef; color: var(--text-secondary); border: 1px solid var(--border-color);
        padding: 2px 8px; font-size: 0.8em; cursor: pointer; border-radius: 4px; transition: var(--transition);
    }
    .more-ip-btn:hover { background-color: #dee2e6; }
    .ip-value-container { position: relative; }
    .ip-dropdown {
        position: absolute; right: 0; top: 110%; background: white; border: 1px solid var(--border-color);
        border-radius: var(--border-radius-sm); box-shadow: 0 4px 12px rgba(0,0,0,0.1); z-index: 1000;
        min-width: 200px; max-height: 200px; overflow-y: auto; display: none;
    }
    .ip-dropdown.show { display: block; }
    .ip-option { padding: 8px 12px; cursor: pointer; }
    .ip-option:hover { background-color: #f8f9fa; }
    .ip-option.active { background-color: #e9ecef; font-weight: bold; }
    .github-corner svg { fill: var(--primary-color); color: #fff; position: fixed; top: 0; border: 0; right: 0; width: 80px; height: 80px; z-index: 10; }
    .github-corner:hover .octo-arm { animation: octocat-wave 560ms ease-in-out; }
    @keyframes octocat-wave { 0%,100%{transform:rotate(0)} 20%,60%{transform:rotate(-25deg)} 40%,80%{transform:rotate(10deg)} }
    .footer {
        text-align: center;
        padding: 25px 15px 25px 15px;
        font-size: 15px;
        border-radius: 0 0 var(--border-radius) var(--border-radius);
        background: transparent;
        backdrop-filter: none;
        color: #7B838A;
    }
    .footer a {
        color: #7B838A;
        text-decoration: none;
        transition: all 0.3s ease;
        position: relative;
        padding-bottom: 2px;
    }
    .footer a::after {
        content: '';
        position: absolute;
        bottom: 0;
        left: 0;
        width: 0;
        height: 1px;
        background: #7B838A;
        transition: width 0.3s ease;
    }
    .footer a:hover {
        color: #3293D4;
    }
    .footer a:hover::after {
        width: 100%;
        background: #3293D4;
    }
    @media (max-width: 768px) {
        body { align-items: flex-start; }
        .container { margin: 10px; }
        .header { flex-direction: column; align-items: flex-start; }
        .header-input { width: 100%; }
        .results-section { grid-template-columns: 1fr; }
        .info-card:first-child { border-bottom: 1px solid var(--border-color); }
    }
    </style>
</head>
<body>
    <a href="https://github.com/cmliu/CF-Workers-CheckSocks5" target="_blank" class="github-corner" aria-label="View source on Github"><svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg></a>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>代理检测工具</h1>
                <p>检测代理服务器的出入口信息 (SOCKS5 / HTTP)</p>
            </div>
            <div class="header-input">
                <input type="text" id="proxyInput" placeholder="例如: socks5://user:pass@host:port" />
                <button id="checkBtn" onclick="checkProxy()">检查代理</button>
            </div>
        </div>
        <div class="results-section">
            <div class="info-card">
                <h3>入口信息</h3>
                <div class="info-content" id="entryInfo">
                    <div class="waiting">请输入代理链接并点击检查</div>
                </div>
            </div>
            <div class="info-card">
                <h3>出口信息</h3>
                <div class="info-content" id="exitInfo">
                    <div class="waiting">请输入代理链接并点击检查</div>
                </div>
            </div>
        </div>
        <div class="footer">{$网络备案_html}</div>
    </div>
      
    <script>
        const 临时TOKEN = '{$临时TOKEN_JS}';
        let currentDomainInfo = null;
        let currentProxyTemplate = null;

        function preprocessProxyUrl(input) {
            let processed = input.trim();
            if (processed.includes('#')) processed = processed.split('#')[0].trim();
            while (processed.startsWith('/')) processed = processed.substring(1);
            if (!processed.includes('://')) processed = 'socks5://' + processed;
            return processed;
        }

        function extractHostFromProxy(proxyUrl) {
            const urlPart = proxyUrl.includes('://') ? proxyUrl.split('://')[1] : proxyUrl;
            const hostPart = urlPart.includes('@') ? urlPart.substring(urlPart.lastIndexOf('@') + 1) : urlPart;
            if (hostPart.startsWith('[')) return hostPart.substring(1, hostPart.indexOf(']:'));
            return hostPart.split(':')[0];
        }
        
        const isIPAddress = host => /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host) || /((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?/.test(host);
        
        function replaceHostInProxy(proxyUrl, newHost) {
            const [protocol, rest] = proxyUrl.split('://');
            let authPart = rest.includes('@') ? rest.substring(0, rest.lastIndexOf('@') + 1) : '';
            let hostPart = rest.includes('@') ? rest.substring(rest.lastIndexOf('@') + 1) : rest;
            const port = hostPart.includes(':') ? hostPart.substring(hostPart.lastIndexOf(':') + 1) : '';
            const processedNewHost = newHost.includes(':') && !newHost.startsWith('[') ? `[\${newHost}]` : newHost;
            return `\${protocol}://\${authPart}\${processedNewHost}:\${port}`;
        }
        
        function formatInfoDisplay(data, containerId, showIPSelector = false) {
            const container = document.getElementById(containerId);
            if (!data || data.error) {
                container.innerHTML = '<div class="error">数据获取失败</div>';
                return;
            }
            
            const ipDisplay = showIPSelector && currentDomainInfo && currentDomainInfo.all_ips.length > 1
                ? `<div class="ip-selector">
                        <span class="ip-text">\${data.resolved_ip || data.ip || 'N/A'}</span>
                        <button class="more-ip-btn" onclick="toggleIPDropdown(event)">\${currentDomainInfo.all_ips.length} IPs</button>
                        <div class="ip-value-container">
                            <div class="ip-dropdown" id="ipDropdown">
                                \${currentDomainInfo.all_ips.map(ip => `<div class="ip-option \${ip === (data.resolved_ip || data.ip) ? 'active' : ''}" onclick="selectIP('\${ip}')">\${ip}</div>`).join('')}
                            </div>
                        </div>
                   </div>`
                : (data.resolved_ip || data.ip || 'N/A');

            container.innerHTML = `
                <div class="info-item"><span class="info-label">IP 地址:</span><span class="info-value">\${ipDisplay}</span></div>
                <div class="info-item"><span class="info-label">ASN:</span><span class="info-value">\${data.asn?.asn ? 'AS' + data.asn.asn : 'N/A'}</span></div>
                <div class="info-item"><span class="info-label">组织:</span><span class="info-value">\${data.asn?.org || 'N/A'}</span></div>
                <div class="info-item"><span class="info-label">位置:</span><span class="info-value">\${data.location?.city || 'N/A'}, \${data.location?.country_code || 'N/A'}</span></div>
                <div class="info-item"><span class="info-label">数据中心:</span><span class="info-value"><span class="\${data.is_datacenter ? 'status-yes' : 'status-no'}">\${data.is_datacenter ? '是' : '否'}</span></span></div>
                <div class="info-item"><span class="info-label">代理/VPN:</span><span class="info-value"><span class="\${data.is_proxy || data.is_vpn ? 'status-yes' : 'status-no'}">\${data.is_proxy || data.is_vpn ? '是' : '否'}</span></span></div>
                <div class="info-item"><span class="info-label">Tor 节点:</span><span class="info-value"><span class="\${data.is_tor ? 'status-yes' : 'status-no'}">\${data.is_tor ? '是' : '否'}</span></span></div>
                <div class="info-item"><span class="info-label">滥用风险:</span><span class="info-value"><span class="\${data.is_abuser ? 'status-yes' : 'status-no'}">\${data.is_abuser ? '是' : '否'}</span></span></div>
            `;
        }

        function toggleIPDropdown(event) {
            event.stopPropagation();
            const dropdown = document.getElementById('ipDropdown');
            dropdown.classList.toggle('show');
            document.addEventListener('click', () => dropdown.classList.remove('show'), { once: true });
        }
        
        async function selectIP(selectedIP) {
            const checkBtn = document.getElementById('checkBtn');
            const entryInfo = document.getElementById('entryInfo');
            const exitInfo = document.getElementById('exitInfo');
            checkBtn.disabled = true;
            entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在获取入口信息...</div>';
            exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在检测代理...</div>';

            try {
                const newProxyUrl = replaceHostInProxy(currentProxyTemplate, selectedIP);
                await performCheck(newProxyUrl, selectedIP, false);
            } catch (error) {
                console.error('切换IP时出错:', error);
                entryInfo.innerHTML = '<div class="error">切换失败</div>';
                exitInfo.innerHTML = '<div class="error">切换失败</div>';
            } finally {
                checkBtn.disabled = false;
            }
        }
        
        async function checkProxy() {
            const proxyInput = document.getElementById('proxyInput');
            const checkBtn = document.getElementById('checkBtn');
            const entryInfo = document.getElementById('entryInfo');
            const exitInfo = document.getElementById('exitInfo');
            
            const rawProxyUrl = proxyInput.value.trim();
            if (!rawProxyUrl) return;

            const proxyUrl = preprocessProxyUrl(rawProxyUrl);
            proxyInput.value = proxyUrl;
            currentProxyTemplate = proxyUrl;
            
            checkBtn.disabled = true;
            entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>解析代理中...</div>';
            exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>解析代理中...</div>';
            
            try {
                await performCheck(proxyUrl, null, true);
            } catch (error) {
                console.error('检测过程中出现错误:', error);
                entryInfo.innerHTML = `<div class="error">\${error.message}</div>`;
                exitInfo.innerHTML = `<div class="error">\${error.message}</div>`;
            } finally {
                checkBtn.disabled = false;
            }
        }

        async function performCheck(proxyUrl, knownIp = null, resolveDomain = true) {
            const entryInfo = document.getElementById('entryInfo');
            const exitInfo = document.getElementById('exitInfo');
            
            const host = extractHostFromProxy(proxyUrl);
            let targetIP = knownIp || host;
            let targetProxyUrl = proxyUrl;
            currentDomainInfo = null;

            if (resolveDomain && !isIPAddress(host)) {
                entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>解析域名中...</div>';
                const response = await fetch(`/socks5/ip-info?ip=\${encodeURIComponent(host)}&token=\${临时TOKEN}`);
                const data = await response.json();
                if (!data.ips) throw new Error(`域名解析失败: \${data.message || '未知错误'}`);
                currentDomainInfo = { all_ips: data.ips, domain: host };
                targetIP = data.resolved_ip;
                targetProxyUrl = replaceHostInProxy(proxyUrl, targetIP);
            }
            
            entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>获取入口信息...</div>';
            exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>检测代理中...</div>';

            const [entryResult, exitResult] = await Promise.allSettled([
                fetch(`/socks5/ip-info?ip=\${encodeURIComponent(targetIP)}&token=\${临时TOKEN}`).then(res => res.json()),
                fetch(`/socks5/check?proxy=\${encodeURIComponent(targetProxyUrl)}`).then(res => res.json())
            ]);
            
            if (entryResult.status === 'fulfilled') {
                formatInfoDisplay(entryResult.value, 'entryInfo', !!currentDomainInfo);
            } else {
                entryInfo.innerHTML = '<div class="error">获取入口信息失败</div>';
            }
            
            if (exitResult.status === 'fulfilled') {
                if (!exitResult.value.success) {
                    exitInfo.innerHTML = `<div class="error">代理检测失败: \${exitResult.value.error || '请检查代理链接'}</div>`;
                } else {
                    formatInfoDisplay(exitResult.value, 'exitInfo', false);
                }
            } else {
                exitInfo.innerHTML = '<div class="error">代理检测失败</div>';
            }
        }
        
        document.getElementById('proxyInput').addEventListener('keypress', e => { if (e.key === 'Enter') checkProxy(); });
    </script>
</body>
</html>
HTML;
}

// --- 3. 主逻辑 & 路由 ---
$path = strtolower(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

// --- Token Generation ---
$hostname = $_SERVER['HTTP_HOST'] ?? 'localhost';
$UA = $_SERVER['HTTP_USER_AGENT'] ?? 'null';
$timestamp = ceil(time() / (60 * 60 * 12));
$临时TOKEN = 双重哈希($hostname . $timestamp . $UA);
$永久TOKEN_final = $永久TOKEN ?: $临时TOKEN;

// --- 新的、更可靠的路由选择 ---
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

} else {
    // 其他所有 /socks5/... 的请求，都视为页面请求
    if ($永久TOKEN && ($永久TOKEN !== $临时TOKEN)) {
        nginx();
    } elseif ($URL302) {
        header("Location: $URL302", true, 302);
    } else {
        $img_url = null;
        if (defined('IMG') && IMG) {
            $imgs = 整理(IMG);
            $img_url = $imgs[array_rand($imgs)];
        }
        HTML($网站图标, $BEIAN, $img_url, $临时TOKEN);
    }
}
?>
