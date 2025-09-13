<?php
// PHP 版本：建议 7.4 或更高
// 依赖扩展：curl, sockets (通常默认启用)
require_once 'config.php';

// --- 1. 配置 & 环境变量读取 ---
$网站图标 = defined('ICO') && ICO ? ICO : 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
$永久TOKEN = defined('TOKEN') && TOKEN ? TOKEN : null;
$BEIAN = defined('BEIAN') && BEIAN ? BEIAN : '© 2025 NAT64/DNS64 Check';

// --- 2. 核心工具函数 ---

function 双重哈希($文本) {
    return strtolower(md5(substr(md5($文本), 7, 20)));
}

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

/**
 * HTML 主页面
 */
function HTML($hostname, $网站图标, $BEIAN, $临时TOKEN) {
    $hostname_js = htmlspecialchars($hostname);
    $网站图标_html = htmlspecialchars($网站图标);
    $临时TOKEN_JS = htmlspecialchars($临时TOKEN);

    echo <<<HTML
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check NAT64/DNS64 可用性检测</title>
    <link rel="icon" href="{$网站图标_html}" type="image/x-icon">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px);
            border-radius: 20px; padding: 30px 30px 5px 30px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 680px; width: 100%;
        }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 {
            color: #333; font-size: 2.5em; margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
        }
        .header p { color: #666; font-size: 1.1em; }
        .form-group { margin-bottom: 30px; }
        .form-group label { display: block; color: #333; font-weight: 600; margin-bottom: 10px; font-size: 1.1em; }
        .dns64-container { position: relative; display: flex; align-items: center; }
        .dns64-input {
            width: 100%; padding: 15px 50px 15px 15px; border: 2px solid #e1e5e9;
            border-radius: 12px; font-size: 1em; transition: all 0.3s ease; background: #fff;
        }
        .dropdown-arrow {
            position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
            width: 36px; height: 36px; cursor: pointer; display: flex;
            align-items: center; justify-content: center; border-radius: 6px;
            transition: all 0.3s ease; color: #666;
        }
        .dropdown-arrow:hover { background: rgba(102, 126, 234, 0.1); color: #667eea; }
        .dropdown-arrow.active { transform: translateY(-50%) rotate(180deg); color: #667eea; }
        .dns64-input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
        .dropdown {
            position: absolute; top: 100%; left: 0; right: 0; background: #fff;
            border: 2px solid #667eea; border-top: none; border-radius: 0 0 12px 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1); z-index: 1000;
            display: none; max-height: 200px; overflow-y: auto;
        }
        .dropdown.show { display: block; }
        .dropdown-item {
            padding: 12px 15px; cursor: pointer; transition: all 0.2s ease;
            border-bottom: 1px solid #f0f0f0; font-size: 0.95em;
        }
        .dropdown-item:last-child { border-bottom: none; }
        .dropdown-item:hover { background: #667eea; color: white; }
        .check-btn {
            width: 100%; padding: 18px; background: linear-gradient(135deg, #667eea, #764ba2);
            color: white; border: none; border-radius: 12px; font-size: 1.2em; font-weight: 600;
            cursor: pointer; transition: all 0.3s ease; /*margin-bottom: 30px;*/
        }
        .check-btn:hover { transform: translateY(-2px); box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3); }
        .check-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
        .result { margin-top: 30px; padding: 25px; border-radius: 12px; display: none; }
        .result.success { background: linear-gradient(135deg, #5cbf60, #4caf50); color: white; }
        .result.error { background: linear-gradient(135deg, #f44336, #e53935); color: white; }
        .result h3 { margin-bottom: 20px; font-size: 1.3em; }
        .copy-section { display: grid; gap: 15px; margin: 20px 0; }
        .copy-item {
            background: rgba(255, 255, 255, 0.2); padding: 15px; border-radius: 8px;
            cursor: pointer; transition: all 0.3s ease; border: 2px solid transparent;
        }
        .copy-item:hover { background: rgba(255, 255, 255, 0.3); border-color: rgba(255, 255, 255, 0.5); }
        .copy-item .label { font-weight: 600; margin-bottom: 5px; }
        .copy-item .value { font-family: 'Courier New', monospace; word-break: break-all; }
        .ip-info { margin-top: 20px; padding: 15px; background: rgba(255, 255, 255, 0.2); border-radius: 8px; }
        .ip-info h4 { margin-bottom: 10px; }
        .loading { display: none; text-align: center; margin: 20px 0; }
        .loading-spinner {
            width: 40px; height: 40px; border-radius: 50%;
            background: conic-gradient(from 0deg, #667eea, #764ba2, #667eea);
            mask: radial-gradient(circle at center, transparent 50%, black 52%);
            -webkit-mask: radial-gradient(circle at center, transparent 50%, black 52%);
            animation: spin 1s linear infinite; margin: 0 auto;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .toast {
            position: fixed; bottom: 20px; right: 20px; background: #5cbf60;
            color: white; padding: 15px 20px; border-radius: 8px; box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            transform: translateX(200%); transition: all 0.3s ease; z-index: 1000;
        }
        .toast.show { transform: translateX(0); }
        .github-corner { position: fixed; top: 0; right: 0; z-index: 1000; }
        .github-corner svg { fill: rgba(102, 126, 234, 0.9); color: #fff; width: 80px; height: 80px; }
        .github-corner:hover .octo-arm { animation: octocat-wave 560ms ease-in-out; }
        @keyframes octocat-wave{0%,100%{transform:rotate(0)}20%,60%{transform:rotate(-25deg)}40%,80%{transform:rotate(10deg)}}

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
        
    </style>
</head>
<body>
    <a href="https://github.com/cmliu/CF-Workers-CheckNAT64" target="_blank" class="github-corner" aria-label="View source on Github">
      <svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
    </a>
    <div class="container">
        <div class="header">
            <h1>🌐 DNS64/NAT64 检测</h1>
            <p>检测DNS64作为NAT64的PROXYIP可用性</p>
        </div>
        <div class="form-group">
            <label for="dns64Input">DNS64 Server/NAT64 Prefix</label>
            <div class="dns64-container">
                <input type="text" id="dns64Input" class="dns64-input" placeholder="请选择预设值或输入自定义值">
                <div class="dropdown-arrow" id="dropdownArrow" onclick="toggleDropdown()">
                    <svg width="12" height="8" viewBox="0 0 12 8" fill="currentColor"><path d="M1 1l5 5 5-5" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </div>
                <div class="dropdown" id="dropdown">
                    <div class="dropdown-item" onclick="selectPreset('2001:67c:2960:6464::/96')">level66.services (德国)</div>
                    <div class="dropdown-item" onclick="selectPreset('dns64.ztvi.hw.090227.xyz')">ZTVI (美国)</div>
                </div>
            </div>
        </div>
        <button class="check-btn" onclick="checkNAT64()">🚀 开始检测</button>
        <div class="loading" id="loading"><div class="loading-spinner"></div></div>
        <div class="result" id="result"></div>
        <div class="footer">{$BEIAN}</div>
    </div>
    <div class="toast" id="toast"></div>
    <script>
        const hostname = '{$hostname_js}';
        const 临时TOKEN = '{$临时TOKEN_JS}';
        const dns64Input = document.getElementById('dns64Input');
        const dropdown = document.getElementById('dropdown');
        const dropdownArrow = document.getElementById('dropdownArrow');
        const STORAGE_KEY = 'dns64_nat64_server';
        
        function loadFromStorage(){try{const a=localStorage.getItem(STORAGE_KEY);if(a){dns64Input.value=a}}catch(a){console.warn("无法读取本地存储:",a)}}
        function saveToStorage(a){try{localStorage.setItem(STORAGE_KEY,a)}catch(a){console.warn("无法保存到本地存储:",a)}}
        function selectPreset(a){dns64Input.value=a;saveToStorage(a);hideDropdown()}
        function showDropdown(){dropdown.classList.add("show");dropdownArrow.classList.add("active")}
        function hideDropdown(){dropdown.classList.remove("show");dropdownArrow.classList.remove("active")}
        function toggleDropdown(){dropdown.classList.contains("show")?hideDropdown():showDropdown()}
        dns64Input.addEventListener('focus',function(){""===this.value.trim()&&showDropdown()});
        dns64Input.addEventListener('blur',function(){setTimeout(()=>{dropdownArrow.matches(":hover")||hideDropdown()},150)});
        dns64Input.addEventListener('input',function(){saveToStorage(this.value)});
        dns64Input.addEventListener('keydown',function(a){"Escape"===a.key&&hideDropdown()});
        document.addEventListener('click',function(a){a.target.closest(".dns64-container")||hideDropdown()});
        function showToast(a){const b=document.getElementById("toast");b.textContent=a;b.classList.add("show");setTimeout(()=>{b.classList.remove("show")},3e3)}
        function copyToClipboard(a){navigator.clipboard.writeText(a).then(()=>{showToast("已复制到剪贴板")}).catch(()=>{const b=document.createElement("textarea");b.value=a;document.body.appendChild(b);b.select();document.execCommand("copy");document.body.removeChild(b);showToast("已复制到剪贴板")})}
        
        async function checkNAT64() {
            const dns64Value = dns64Input.value.trim();
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            const checkBtn = document.querySelector('.check-btn');
            
            loading.style.display = 'block';
            result.style.display = 'none';
            checkBtn.disabled = true;
            
            let retryCount = 0;
            let lastError = null;
            
            async function performCheck() {
                // 【API URL】
                const apiUrl = dns64Value ? `/nat64/check?nat64=\${encodeURIComponent(dns64Value)}` : `/nat64/check`;
                const checkResponse = await fetch(apiUrl);
                const checkData = await checkResponse.json();
                if (!checkData.success) {
                    throw new Error(checkData.message || '检测失败');
                }
                return checkData;
            }
            
            while (retryCount < 3) {
                retryCount++;
                try {
                    const checkData = await performCheck();
                    const nat64Value = `[\${checkData.nat64_ipv6}]`;
                    const proxyIPValue = `ProxyIP.\${checkData.nat64_ipv6.replace(/:/g, '-')}.ip.090227.xyz`;
                    result.className = 'result success';
                    result.innerHTML = `
                        <h3>✅ 检测成功</h3>
                        <p>此DNS64/NAT64服务器可用作PROXYIP</p>
                        \${retryCount > 1 ? `<p style="color: rgba(255,255,255,0.8); font-size: 0.9em;">经过 \${retryCount} 次尝试后成功</p>` : ''}
                        <div class="copy-section">
                            <div class="copy-item" onclick="copyToClipboard('\${nat64Value}')"><div class="label">PROXYIP (IPv6格式)</div><div class="value">\${nat64Value}</div></div>
                            <div class="copy-item" onclick="copyToClipboard('\${proxyIPValue}')"><div class="label">PROXYIP (域名格式)</div><div class="value">\${proxyIPValue}</div></div>
                            <div class="copy-item" onclick="copyToClipboard('\${checkData.nat64_prefix}')"><div class="label">NAT64 (IPv6前缀)</div><div class="value">\${checkData.nat64_prefix}</div></div>
                        </div>
                        <div id="ipInfo" class="ip-info" style="display: none;">
                            <h4>🌍 落地IP信息</h4>
                            <div id="ipInfoContent"></div>
                        </div>
                    `;
                    if (checkData.trace_data && checkData.trace_data.ip) {
                        try {
                            // 【API URL 已修改】
                            const ipInfoResponse = await fetch(`/nat64/ip-info?token=\${临时TOKEN}&ip=\${checkData.trace_data.ip}`);
                            const ipInfoData = await ipInfoResponse.json();
                            if (ipInfoData.status === 'success') {
                                document.getElementById('ipInfo').style.display = 'block';
                                document.getElementById('ipInfoContent').innerHTML = `
                                    <p><strong>IP地址：</strong>\${ipInfoData.query}</p>
                                    <p><strong>国家：</strong>\${ipInfoData.country} (\${ipInfoData.countryCode})</p>
                                    <p><strong>地区：</strong>\${ipInfoData.regionName}, \${ipInfoData.city}</p>
                                    <p><strong>ISP：</strong>\${ipInfoData.isp}</p>
                                    <p><strong>AS：</strong>\${ipInfoData.as}</p>
                                `;
                            }
                        } catch (ipError) {
                            console.error('获取IP信息失败:', ipError);
                        }
                    }
                    result.style.display = 'block';
                    loading.style.display = 'none';
                    checkBtn.disabled = false;
                    return;
                } catch (error) {
                    console.error(`检测错误 (第\${retryCount}次尝试):`, error);
                    lastError = error;
                    if (retryCount < 3) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                        continue;
                    }
                }
            }
            
            result.className = 'result error';
            result.innerHTML = `
                <h3>❌ 检测失败</h3>
                <p>经过 3 次尝试后仍然失败</p>
                <p><strong>最后一次错误：</strong>\${lastError?.message || '未知错误'}</p>
                <p>此DNS64/NAT64服务器不可用作PROXYIP</p>
            `;
            result.style.display = 'block';
            loading.style.display = 'none';
            checkBtn.disabled = false;
        }
        
        dns64Input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                checkNAT64();
            }
        });
        loadFromStorage();
    </script>
</body>
</html>
HTML;
}

// --- 3. 主逻辑 & 路由 ---
$path = strtolower(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

$hostname = $_SERVER['HTTP_HOST'] ?? 'localhost';
$UA = $_SERVER['HTTP_USER_AGENT'] ?? 'null';
$timestamp = ceil(time() / (60 * 60 * 8));
$临时TOKEN = 双重哈希($hostname . $timestamp . $UA);
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
} else {
    HTML($hostname, $网站图标, $BEIAN, $临时TOKEN);
}
?>
