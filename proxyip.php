<?php
// PHP 版本：建议 7.4 或更高
// 依赖扩展：curl, sockets (通常默认启用)
require_once 'config.php';

// --- 1. 配置 & 环境变量读取 ---
$网站图标 = defined('ICO') && ICO ? ICO : 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
$永久TOKEN = defined('TOKEN') && TOKEN ? TOKEN : null;
$URL302 = defined('URL302') ? URL302 : null;
$URL = defined('URL') ? URL : null;
$BEIAN = defined('BEIAN') && BEIAN ? BEIAN : '© 2025 ProxyIP Check';

// --- 2. 核心工具函数 ---
function isExcludedIP($ip) {
    $is_ipv4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    $is_ipv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);

    if (!$is_ipv4 && !$is_ipv6) {
        return false; // 如果不是有效的IP地址，则不排除
    }

    $excluded_cidrs = [
        // 1. Cloudflare 自身的IP地址段 (模拟Worker无法连接自身的限制)
        '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '104.16.0.0/12', '108.162.192.0/18', '131.0.72.0/22',
        '141.101.64.0/18', '162.158.0.0/15', '172.64.0.0/13',
        '173.245.48.0/20', '188.114.96.0/20', '190.93.240.0/20',
        '197.234.240.0/22', '198.41.128.0/17',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
        '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
        '2c0f:f248::/32',

        // 2. 著名的公共DNS服务
        '8.8.8.0/24', '8.8.4.0/24',  // Google DNS
        '2001:4860:4860::8888/128', '2001:4860:4860::8844/128',  // Google DNS IPv6
        '9.9.9.9/32', '149.112.112.112/32',  // Quad9 DNS
        '2620:fe::fe/128', '2620:fe::9/128',  // Quad9 DNS IPv6
        '208.67.222.222/32', '208.67.220.220/32',  // OpenDNS
        '2620:119:35::35/128', '2620:119:53::53/128',  // OpenDNS IPv6
        '1.1.1.0/24', '1.0.0.0/24',  // Cloudflare DNS
        '2606:4700::/32', '2606:4700:1111::/32',  // Cloudflare DNS IPv6
        '94.140.14.14/32', '94.140.15.15/32',  // AdGuard DNS
        '2a10:50c0::ad1:ff/128', '2a10:50c0::ad2:ff/128',  // AdGuard DNS IPv6
        '185.228.168.9/32', '185.228.169.9/32',  // CleanBrowsing DNS
        '185.228.168.168/32', '185.228.169.168/32',  // CleanBrowsing DNS IPv6
        '198.101.242.72/32', '198.101.242.74/32',  // Alternate DNS
        '2001:67c:2e8::/32', '2001:67c:2e8:1::/32',  // Alternate DNS IPv6
        '76.76.19.19/32', '76.76.20.20/32',  // Control D DNS
        '2001:67c:2e8::/32', '2001:67c:2e8:1::/32',  // Control D DNS IPv6
        '84.200.69.80/32', '84.200.70.40/32',  // DNS.Watch
        '2001:1608:10:25::/32', '2001:1608:10:25:1::/32',  // DNS.Watch IPv6
        '185.121.177.177/32', '185.121.177.178/32',  // OpenNIC DNS
        '2001:67c:2e8::/32', '2001:67c:2e8:1::/32',  // OpenNIC DNS IPv6
    ];

    if ($is_ipv4) {
        $ip_long = ip2long($ip);
        foreach ($excluded_cidrs as $cidr) {
            if (strpos($cidr, ':') === false) { // 只与IPv4的CIDR比较
                list($subnet, $mask) = explode('/', $cidr);
                $subnet_long = ip2long($subnet);
                $mask_long = -1 << (32 - (int)$mask);
                if (($ip_long & $mask_long) == ($subnet_long & $mask_long)) {
                    return true;
                }
            }
        }
    }

    if ($is_ipv6) {
        $ip_bin = inet_pton($ip);
        foreach ($excluded_cidrs as $cidr) {
            if (strpos($cidr, ':') !== false) { // 只与IPv6的CIDR比较
                list($subnet, $mask) = explode('/', $cidr);
                $subnet_bin = inet_pton($subnet);
                if ($subnet_bin === false) continue;
                
                $mask_bin = '';
                $full_bytes = floor($mask / 8);
                for ($i = 0; $i < $full_bytes; $i++) {
                    $mask_bin .= "\xff";
                }
                $remaining_bits = $mask % 8;
                if ($remaining_bits > 0) {
                    $mask_bin .= chr(0xff << (8 - $remaining_bits));
                }
                $mask_bin = str_pad($mask_bin, 16, "\0");

                if (($ip_bin & $mask_bin) === ($subnet_bin & $mask_bin)) {
                    return true;
                }
            }
        }
    }
    return false;
}

function 双重哈希($文本) {
    return md5(substr(md5($文本), 7, 20));
}

function 构建TLS握手_binary() {
    return hex2bin('16030107a30100079f0303af1f4d78be2002cf63e8c727224cf1ee4a8ac89a0ad04bc54cbed5cd7c830880203d8326ae1d1d076ec749df65de6d21dec7371c589056c0a548e31624e121001e0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007361a1a0000000a000c000acaca11ec001d00170018fe0d00ba0000010001fc00206a2fb0535a0a5e565c8a61dcb381bab5636f1502bbd09fe491c66a2d175095370090dd4d770fc5e14f4a0e13cfd919a532d04c62eb4a53f67b1375bf237538cea180470d942bdde74611afe80d70ad25afb1d5f02b2b4eed784bc2420c759a742885f6ca982b25d0fdd7d8f618b7f7bc10172f61d446d8f8a6766f3587abbae805b8ef40fcb819194ac49e91c6c3762775f8dc269b82a21ddccc9f6f43be62323147b411475e47ea2c4efe52ef2cef5c7b32000d00120010040308040401050308050501080606010010000e000c02683208687474702f312e31000b0002010000050005010000000044cd00050003026832001b00030200020017000000230000002d000201010012000000000010000e00000b636861746770742e636f6dff01000100002b0007061a1a03040303003304ef04edcaca00010011ec04c05eac5510812e46c13826d28279b13ce62b6464e01ae1bb6d49640e57fb3191c656c4b0167c246930699d4f467c19d60dacaa86933a49e5c97390c3249db33c1aa59f47205701419461569cb01a22b4378f5f3bb21d952700f250a6156841f2cc952c75517a481112653400913f9ab58982a3f2d0010aba5ae99a2d69f6617a4220cd616de58ccbf5d10c5c68150152b60e2797521573b10413cb7a3aab25409d426a5b64a9f3134e01dc0dd0fc1a650c7aafec00ca4b4dddb64c402252c1c69ca347bb7e49b52b214a7768657a808419173bcbea8aa5a8721f17c82bc6636189b9ee7921faa76103695a638585fe678bcbb8725831900f808863a74c52a1b2caf61f1dec4a9016261c96720c221f45546ce0e93af3276dd090572db778a865a07189ae4f1a64c6dbaa25a5b71316025bd13a6012994257929d199a7d90a59285c75bd4727a8c93484465d62379cd110170073aad2a3fd947087634574315c09a7ccb60c301d59a7c37a330253a994a6857b8556ce0ac3cda4c6fe3855502f344c0c8160313a3732bce289b6bda207301e7b318277331578f370ccbcd3730890b552373afeb162c0cb59790f79559123b2d437308061608a704626233d9f73d18826e27f1c00157b792460eda9b35d48b4515a17c6125bdb96b114503c99e7043b112a398888318b956a012797c8a039a51147b8a58071793c14a3611fb0424e865f48a61cac7c43088c634161cea089921d229e1a370effc5eff2215197541394854a201a6ebf74942226573bb95710454bd27a52d444690837d04611b676269873c50c3406a79077e6606478a841f96f7b076a2230fd34f3eea301b77bf00750c28357a9df5b04f192b9c0bbf4f71891f1842482856b021280143ae74356c5e6a8e3273893086a90daa7a92426d8c370a45e3906994b8fa7a57d66b503745521e40948e83641de2a751b4a836da54f2da413074c3d856c954250b5c8332f1761e616437e527c0840bc57d522529b9259ccac34d7a3888f0aade0a66c392458cc1a698443052413217d29fbb9a1124797638d76100f82807934d58f30fcff33197fc171cfa3b0daa7f729591b1d7389ad476fde2328af74effd946265b3b81fa33066923db476f71babac30b590e05a7ba2b22f86925abca7ef8058c2481278dd9a240c8816bba6b5e6603e30670dffa7e6e3b995b0b18ec404614198a43a07897d84b439878d179c7d6895ac3f42ecb7998d4491060d2b8a5316110830c3f20a3d9a488a85976545917124c1eb6eb7314ea9696712b7bcab1cfd2b66e5a85106b2f651ab4b8a145e18ac41f39a394da9f327c5c92d4a297a0c94d1b8dcc3b111a700ac8d81c45f983ca029fd2887ad4113c7a23badf807c6d0068b4fa7148402aae15cc55971b57669a4840a22301caaec392a6ea6d46dab63890594d41545ebc2267297e3f4146073814bb3239b3e566684293b9732894193e71f3b388228641bb8be6f5847abb9072d269cb40b353b6aa3259ccb7e438d6a37ffa8cc1b7e4911575c41501321769900d19792aa3cfbe58b0aaf91c91d3b63900697279ad6c1aa44897a07d937e0d5826c24439420ca5d8a63630655ce9161e58d286fc885fcd9b19d096080225d16c89939a24aa1e98632d497b5604073b13f65bdfddc1de4b40d2a829b0521010c5f0f241b1ccc759049579db79983434fac2748829b33f001d0020a8e86c9d3958e0257c867e59c8082238a1ea0a9f2cac9e41f9b3cb0294f34b484a4a000100002900eb00c600c0afc8dade37ae62fa550c8aa50660d8e73585636748040b8e01d67161878276b1ec1ee2aff7614889bb6a36d2bdf9ca097ff6d7bf05c4de1d65c2b8db641f1c8dfbd59c9f7e0fed0b8e0394567eda55173d198e9ca40883b291ab4cada1a91ca8306ca1c37e047ebfe12b95164219b06a24711c2182f5e37374d43c668d45a3ca05eda90e90e510e628b4cfa7ae880502dae9a70a8eced26ad4b3c2f05d77f136cfaa622e40eb084dd3eb52e23a9aeff6ae9018100af38acfd1f6ce5d8c53c4a61c547258002120fe93e5c7a5c9c1a04bf06858c4dd52b01875844e15582dd566d03f41133183a0');
}

/**
 * 核心函数：验证代理IP是否有效
 */
function 验证反代IP($反代IP地址, $指定端口) {
    // 模拟环境限制：检查IP是否在公共服务排除列表中
    if (isExcludedIP($反代IP地址)) {
        return [false, "目标IP {$反代IP地址} 属于已知的公共服务，不能作为ProxyIP", -1];
    }
    
    // 功能检测：执行原始的TLS握手重试逻辑
    $最大重试次数 = 4;
    $最后错误 = null;
    $开始时间 = microtime(true);
    $二进制握手 = 构建TLS握手_binary();

    for ($重试次数 = 0; $重试次数 < $最大重试次数; $重试次数++) {
        $socket = null;
        try {
            $连接超时 = 1.0 + ($重试次数 * 0.5);
            $socket = @stream_socket_client("tcp://$反代IP地址:$指定端口", $errno, $errstr, $连接超时);

            if ($socket === false) {
                $最后错误 = "第" . ($重试次数 + 1) . "次重试: 连接失败 ($errno) - $errstr";
                $不应重试的错误 = ['Connection refused', 'No route to host', 'Network is unreachable', 'Host unreachable'];
                foreach ($不应重试的错误 as $errorPattern) {
                    if (stripos($errstr, $errorPattern) !== false) {
                        $最后错误 = "连接失败，无需重试: $errstr";
                        break 2;
                    }
                }
                continue;
            }

            stream_set_timeout($socket, floor($连接超时), ($连接超时 - floor($连接超时)) * 1000000);

            if (fwrite($socket, $二进制握手) === false) {
                throw new Exception("发送TLS握手失败");
            }

            $返回数据 = fread($socket, 2048);
            $元数据 = stream_get_meta_data($socket);

            if ($元数据['timed_out']) {
                throw new Exception("读取响应超时");
            }
            if ($返回数据 === false || strlen($返回数据) === 0) {
                throw new Exception("未收到任何响应数据");
            }

            if (ord($返回数据[0]) === 0x16) {
                $响应时间 = round((microtime(true) - $开始时间) * 1000);
                return [true, "第" . ($重试次数 + 1) . "次验证有效ProxyIP", $响应时间];
            } else {
                throw new Exception("收到非TLS响应(0x" . str_pad(dechex(ord($返回数据[0])), 2, '0', STR_PAD_LEFT) . ")");
            }
        } catch (Exception $e) {
            $最后错误 = "第" . ($重试次数 + 1) . "次重试失败: " . $e->getMessage();
        } finally {
            if (is_resource($socket)) {
                fclose($socket);
            }
        }
        
        if ($重试次数 < $最大重试次数 - 1) {
            usleep(200000 + ($重试次数 * 300000));
        }
    }
    return [false, $最后错误 ?: '所有重试均失败', -1];
}

/**
 * 包装函数，获取并返回IP的地理位置
 */
function CheckProxyIP($proxyIP, $country_fallback = 'N/A') {
    $portRemote = 443;
    $ip = $proxyIP;
    
    if (strpos($proxyIP, '.tp') !== false) {
        if (preg_match('/\.tp(\d+)\./', $proxyIP, $matches)) {
            $portRemote = intval($matches[1]);
        }
    } elseif (preg_match('/^(\[.+\]):(\d+)$/', $proxyIP, $matches)) {
        $ip = $matches[1];
        $portRemote = intval($matches[2]);
    } elseif (strpos($proxyIP, ':') !== false && !strpos($proxyIP, ']:')) {
        $parts = explode(':', $proxyIP);
        if (count($parts) > 2) {
            $portRemote = intval(array_pop($parts));
            $ip = implode(':', $parts);
        } else {
            $ip = $parts[0];
            $portRemote = intval($parts[1]);
        }
    }

    try {
        $ip_to_check = trim($ip, '[]');
        $isSuccessful = 验证反代IP($ip_to_check, $portRemote);
        
        $final_country = $country_fallback;

        if ($isSuccessful[0]) {
            try {
                $ch = curl_init("http://ip-api.com/json/" . urlencode($ip_to_check) . "?fields=countryCode");
                curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
                $geo_response = curl_exec($ch);
                curl_close($ch);

                $geo_data = json_decode($geo_response, true);
                if (isset($geo_data['countryCode']) && !empty($geo_data['countryCode'])) {
                    $final_country = $geo_data['countryCode'];
                }
            } catch (Exception $e) {
                // geo查询失败不影响整体结果
            }
        }
        
        return [
            'success' => $isSuccessful[0],
            'proxyIP' => $ip_to_check,
            'portRemote' => $portRemote,
            'country' => $final_country,
            'responseTime' => $isSuccessful[2] ?? -1,
            'message' => $isSuccessful[1],
            'timestamp' => gmdate('Y-m-d\TH:i:s.v\Z'),
        ];
    } catch (Exception $e) {
        return [
            'success' => false,
            'proxyIP' => -1,
            'portRemote' => -1,
            'country' => $country_fallback,
            'responseTime' => -1,
            'message' => $e->getMessage(),
            'timestamp' => gmdate('Y-m-d\TH:i:s.v\Z'),
        ];
    }
}

function resolveDomain($domain) {
    $domain = explode(':', $domain)[0];
    try {
        $mh = curl_multi_init();
        $urls = ['A' => "https://1.1.1.1/dns-query?name=" . urlencode($domain) . "&type=A", 'AAAA' => "https://1.1.1.1/dns-query?name=" . urlencode($domain) . "&type=AAAA"];
        $chs = [];
        foreach ($urls as $type => $url) {
            $ch = curl_init();
            curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ['Accept: application/dns-json'], CURLOPT_TIMEOUT => 5]);
            curl_multi_add_handle($mh, $ch);
            $chs[$type] = $ch;
        }
        $running = null;
        do { curl_multi_exec($mh, $running); } while ($running);
        $ips = [];
        $ipv4Data = json_decode(curl_multi_getcontent($chs['A']), true);
        if (isset($ipv4Data['Answer'])) {
            foreach ($ipv4Data['Answer'] as $record) {
                if ($record['type'] === 1) $ips[] = $record['data'];
            }
        }
        $ipv6Data = json_decode(curl_multi_getcontent($chs['AAAA']), true);
        if (isset($ipv6Data['Answer'])) {
            foreach ($ipv6Data['Answer'] as $record) {
                if ($record['type'] === 28) $ips[] = '[' . $record['data'] . ']';
            }
        }
        foreach ($chs as $ch) { curl_multi_remove_handle($mh, $ch); }
        curl_multi_close($mh);
        if (empty($ips)) throw new Exception('No A or AAAA records found');
        return $ips;
    } catch (Exception $e) {
        throw new Exception('DNS resolution failed: ' . $e->getMessage());
    }
}

/**
 * 输出nginx欢迎页面
 */
function nginx() {
    header('Content-Type: text/html; charset=UTF-8');
    echo <<<HTML
<!DOCTYPE html>
<html>
    <head>
        <title>Welcome to nginx!</title>
        <style>
            body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
        </style>
    </head>
    <body>
        <h1>Welcome to nginx!</h1>
        <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
        <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/> Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
        <p><em>Thank you for using nginx.</em></p>
    </body>
</html>
HTML;
}

/**
 * 输出主页面的HTML, CSS和JS
 */
function HTML($hostname, $网站图标, $BEIAN, $临时TOKEN) {
    $hostname_js = htmlspecialchars($hostname, ENT_QUOTES, 'UTF-8');
    $网站图标_html = htmlspecialchars($网站图标, ENT_QUOTES, 'UTF-8');
    $临时TOKEN_JS = htmlspecialchars($临时TOKEN, ENT_QUOTES, 'UTF-8');
    $BEIAN_html = $BEIAN;

    header('Content-Type: text/html; charset=UTF-8');
    echo <<<HTML
<!DOCTYPE html>
<html lang="zh-CN">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check ProxyIP - 代理IP检测服务</title>
    <link rel="icon" href="{$网站图标_html}" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #3498db; --primary-dark: #2980b9; --secondary-color: #1abc9c;
            --success-color: #2ecc71; --warning-color: #f39c12; --error-color: #e74c3c;
            --bg-primary: #ffffff; --bg-secondary: #f8f9fa; --bg-tertiary: #e9ecef;
            --text-primary: #2c3e50; --text-secondary: #6c757d; --text-light: #adb5bd;
            --border-color: #dee2e6; --shadow-sm: 0 2px 4px rgba(0,0,0,0.1);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.1); --shadow-lg: 0 10px 25px rgba(0,0,0,0.15);
            --border-radius: 12px; --border-radius-sm: 8px; --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6; color: var(--text-primary);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; position: relative; overflow-x: hidden;
        }
        .container { max-width: 1000px; margin: 40px auto 10px auto; padding: 20px 20px 10px 20px; }
        .header { text-align: center; margin-bottom: 50px; animation: fadeInDown 0.8s ease-out; }
        .main-title {
            font-size: clamp(2.5rem, 5vw, 4rem); font-weight: 700;
            background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
            margin-bottom: 16px; text-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .card {
            background: var(--bg-primary); border-radius: var(--border-radius);
            padding: 32px; box-shadow: var(--shadow-lg); margin-bottom: 32px;
            border: 1px solid var(--border-color); transition: var(--transition);
            animation: fadeInUp 0.8s ease-out; backdrop-filter: blur(20px);
            position: relative; overflow: hidden;
        }
        .card::before {
            content: ""; position: absolute; top: 0; left: 0; right: 0; height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
        }
        .form-section { margin-bottom: 32px; }
        .form-label { display: block; font-weight: 600; font-size: 1.1rem; margin-bottom: 12px; color: var(--text-primary); }
        .input-group { display: flex; gap: 16px; align-items: flex-end; flex-wrap: wrap; }
        .input-wrapper { flex: 1; min-width: 300px; position: relative; }
        .form-input {
            width: 100%; padding: 16px 20px; border: 2px solid var(--border-color);
            border-radius: var(--border-radius-sm); font-size: 16px; font-family: inherit;
            transition: var(--transition); background: var(--bg-primary); color: var(--text-primary);
        }
        .form-input:focus {
            outline: none; border-color: var(--primary-color);
            box-shadow: 0 0 0 4px rgba(52, 152, 219, 0.1);
        }
        .btn {
            padding: 16px 32px; border: none; border-radius: var(--border-radius-sm);
            font-size: 16px; font-weight: 600; font-family: inherit; cursor: pointer;
            transition: var(--transition); text-decoration: none; display: inline-flex;
            align-items: center; justify-content: center; gap: 8px; min-width: 120px;
        }
        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: white; box-shadow: var(--shadow-md);
        }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(52, 152, 219, 0.3); }
        .btn-primary:disabled { background: var(--text-light); cursor: not-allowed; }
        .loading-spinner {
            width: 20px; height: 20px; border: 2px solid rgba(255,255,255,0.3);
            border-top: 2px solid white; border-radius: 50%; animation: spin 1s linear infinite;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .result-section { margin-top: 32px; opacity: 0; transform: translateY(20px); transition: var(--transition); }
        .result-section.show { opacity: 1; transform: translateY(0); }
        .result-card {
            border-radius: var(--border-radius-sm); padding: 24px; margin-bottom: 16px;
            border-left: 4px solid; position: relative; overflow: hidden;
        }
        .result-success { background: #f0fff4; border-color: var(--success-color); color: #2f855a; }
        .result-error { background: #fff5f5; border-color: var(--error-color); color: #c53030; }
        .result-warning { background: #fffaf0; border-color: var(--warning-color); color: #dd6b20; }
        .ip-grid { display: grid; gap: 16px; margin-top: 20px; }
        .ip-item {
            background: rgba(255,255,255,0.9); border: 1px solid var(--border-color);
            border-radius: var(--border-radius-sm); padding: 20px; transition: var(--transition);
        }
        .ip-status-line { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .status-icon { font-size: 18px; margin-left: auto; }
        .copy-btn {
            background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 6px 12px;
            border-radius: 6px; font-size: 14px; cursor: pointer; transition: var(--transition);
            display: inline-flex; align-items: center; gap: 4px; margin: 4px 0;
        }
        .copy-btn:hover { background: var(--primary-color); color: white; border-color: var(--primary-color); }
        .copy-btn.copied { background: var(--success-color); color: white; border-color: var(--success-color); }
        .tag { padding: 4px 8px; border-radius: 16px; font-size: 12px; font-weight: 500; }
        .tag-country { background: #e3f2fd; color: #1976d2; }
        .tag-as { background: #f3e5f5; color: #7b1fa2; }
        .api-docs {
            background: var(--bg-primary); border-radius: var(--border-radius); padding: 32px;
            box-shadow: var(--shadow-lg); animation: fadeInUp 0.8s ease-out 0.2s both;
        }
        .section-title {
            font-size: 1.8rem; font-weight: 700; color: var(--text-primary);
            margin-bottom: 24px; position: relative; padding-bottom: 12px;
        }
        .section-title::after {
            content: ""; position: absolute; bottom: 0; left: 0; width: 60px; height: 3px;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
            border-radius: 2px;
        }
        .code-block {
            background: #2d3748; color: #e2e8f0; padding: 20px;
            border-radius: var(--border-radius-sm); font-family: 'Monaco', 'Menlo', monospace;
            font-size: 14px; overflow-x: auto; margin: 16px 0; border: 1px solid #4a5568;
        }
        .footer { text-align: center; padding: 20px 20px 20px; color: rgba(255,255,255,0.8); font-size: 14px; margin-top: 20px; }
        .footer a { color: rgba(255,255,255,0.9); text-decoration: none; transition: color 0.3s; }
        .footer a:hover { color: white; }
        .github-corner { position: fixed; top: 0; right: 0; z-index: 1000; }
        .github-corner svg { fill: rgba(255,255,255,0.9); color: var(--primary-color); width: 80px; height: 80px; }
        .toast {
            position: fixed; bottom: 20px; right: 20px; background: var(--text-primary);
            color: white; padding: 12px 20px; border-radius: var(--border-radius-sm);
            box-shadow: var(--shadow-lg); transform: translateY(100px); opacity: 0;
            transition: var(--transition); z-index: 1000;
        }
        .toast.show { transform: translateY(0); opacity: 1; }
        .tooltip {
            position: relative;
            display: inline-block;
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            opacity: 0;
            background-color: #2c3e50;
            color: #fff;
            text-align: center;
            border-radius: 8px;
            padding: 8px 12px;
            position: absolute;
            z-index: 100;
            bottom: 125%;
            left: auto;
            right: 0;
            white-space: nowrap;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            font-size: 14px;
            transition: opacity 0.3s, visibility 0.3s;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
      
        @keyframes fadeInDown{from{opacity:0;transform:translateY(-30px)}to{opacity:1;transform:translateY(0)}}
        @keyframes fadeInUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
        @media (max-width: 768px) {
            .container { margin-top: 20px; }
            .card, .api-docs { padding: 24px; }
            .input-group { flex-direction: column; align-items: stretch; }
            .btn { width: 100%; }
            .tooltip .tooltiptext {
                white-space: normal;
                word-wrap: break-word;
                width: auto;
                min-width: 140px;
                max-width: 240px;
                font-size: 11px;
            }
        }
    </style>
    </head>
    <body>
    <a href="https://github.com/cmliu/CF-Workers-CheckProxyIP" target="_blank" class="github-corner" aria-label="View source on Github">
        <svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
    </a>

    <div class="container">
        <header class="header">
        <h1 class="main-title">Check ProxyIP</h1>
        </header>

        <div class="card">
        <div class="form-section">
            <label for="proxyip" class="form-label">🔍 输入 ProxyIP 地址</label>
            <div class="input-group">
            <div class="input-wrapper">
                <input type="text" id="proxyip" class="form-input" placeholder="例如: 1.2.3.4:443 或 example.com" autocomplete="off">
            </div>
            <button id="checkBtn" class="btn btn-primary" onclick="checkProxyIP()">
                <span class="btn-text">检测</span>
                <div class="loading-spinner" style="display: none;"></div>
            </button>
            </div>
        </div>
        
        <div id="result" class="result-section"></div>
        </div>
        
        <div class="api-docs">
        <h2 class="section-title">🤔 什么是 ProxyIP ？</h2>
        <p style="margin-bottom: 16px; line-height: 1.8; color: var(--text-secondary);">
            在 Cloudflare Workers 环境中，ProxyIP 特指那些能够成功代理连接到 Cloudflare 服务的第三方 IP 地址。
        </p>
        <h3 style="color: var(--text-primary); margin: 24px 0 16px;">🔧 技术原理</h3>
        <p style="margin-bottom: 16px; line-height: 1.8; color: var(--text-secondary);">
            根据 Cloudflare Workers 的 <a href="https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/" target="_blank" style="color: var(--primary-color); text-decoration: none;">TCP Sockets 官方文档</a> 说明，存在以下技术限制：
        </p>
        <div class="code-block" style="background: #fff3cd; color: #856404; border-left: 4px solid var(--warning-color);">
            ⚠️ Outbound TCP sockets to <a href="https://www.cloudflare.com/ips/" target="_blank" >Cloudflare IP ranges ↗</a> are temporarily blocked, but will be re-enabled shortly.
        </div>
        <p style="margin: 16px 0; line-height: 1.8; color: var(--text-secondary);">
            这意味着 Cloudflare Workers 无法直接连接到 Cloudflare 自有的 IP 地址段。为了解决这个限制，需要借助第三方云服务商的服务器作为"跳板"。
        </p>
        </div>
 
        <div class="api-docs" style="margin-top: 50px;">
          <h2 class="section-title">📚 API 文档</h2>
          <p style="margin-bottom: 24px; color: var(--text-secondary); font-size: 1.1rem;">
          提供简单易用的 RESTful API 接口，支持批量检测和域名解析
          </p>
          <h3 style="color: var(--text-primary); margin: 24px 0 16px;">📍 检查ProxyIP</h3>
          <div class="code-block">
              <strong style="color: #68d391;">GET</strong> /proxyip/check?proxyip=<span class="highlight">YOUR_PROXY_IP</span>
          </div>
      
          <h3 style="color: var(--text-primary); margin: 24px 0 16px;">💡 使用示例</h3>
          <div class="code-block">
              curl "https://$hostname/proxyip/check?proxyip=1.2.3.4:443"
          </div>

          <h3 style="color: var(--text-primary); margin: 24px 0 16px;">🔗 响应Json格式</h3>
          <div class="code-block">
{<br>
&nbsp;&nbsp;"success": true | false, // 代理 IP 是否有效<br>
&nbsp;&nbsp;"proxyIP": "1.2.3.4", // 如果有效,返回代理 IP,否则为 -1<br>
&nbsp;&nbsp;"portRemote": 443, // 如果有效,返回端口,否则为 -1<br>
&nbsp;&nbsp;"country": "US", // 执行此次请求的服务器标识<br>
&nbsp;&nbsp;"responseTime": "166", // 如果有效,返回响应毫秒时间,否则为 -1<br>
&nbsp;&nbsp;"message": "第1次验证有效ProxyIP", // 返回验证信息<br>
&nbsp;&nbsp;"timestamp": "2025-06-03T17:27:52.946Z" // 检查时间<br>
}<br>
            </div>
        </div>
      
        <div class="footer">{$BEIAN_html}</div>
    </div>

    <div id="toast" class="toast"></div>

    <script>
    const 临时TOKEN = '{$临时TOKEN_JS}';
    let isChecking = false;
    const ipCheckResults = new Map();
    let pageLoadTimestamp;

    function calculateTimestamp() {
      const currentDate = new Date();
      return Math.ceil(currentDate.getTime() / (1000 * 60 * 13));
    }

    function isValidProxyIPFormat(input) {
      const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$/;
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const ipv6Regex = /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/;
      const withPortRegex = /^.+:\\d+$/;
      const tpPortRegex = /^.+\\.tp\\d+\\./;
      return domainRegex.test(input) || ipv4Regex.test(input) || ipv6Regex.test(input) || withPortRegex.test(input) || tpPortRegex.test(input);
    }

    document.addEventListener('DOMContentLoaded', function() {
      pageLoadTimestamp = calculateTimestamp();
      const input = document.getElementById('proxyip');
      input.focus();
      // 适配URL美化后的路径检查
      const pathSegments = window.location.pathname.split('/').filter(Boolean);
      let autoCheckValue = null;
      if (pathSegments.length > 1 && pathSegments[0] === 'proxyip') {
          autoCheckValue = decodeURIComponent(pathSegments.slice(1).join('/'));
      } else if (pathSegments.length === 1 && pathSegments[0] !== 'proxyip' && pathSegments[0] !== '') {
          autoCheckValue = decodeURIComponent(pathSegments[0]);
      }
      
      if (autoCheckValue && isValidProxyIPFormat(autoCheckValue)) {
        input.value = autoCheckValue;
        const newUrl = new URL(window.location);
        newUrl.pathname = '/proxyip'; // 统一URL为干净路径
        window.history.replaceState({}, '', newUrl);
        setTimeout(() => checkProxyIP(), 500);
      } else {
        try {
          const lastSearch = localStorage.getItem('lastProxyIP');
          if (lastSearch && isValidProxyIPFormat(lastSearch)) {
            input.value = lastSearch;
          }
        } catch (error) { console.log('读取历史记录失败:', error); }
      }
      
      input.addEventListener('keypress', event => { if (event.key === 'Enter' && !isChecking) checkProxyIP(); });
      document.addEventListener('click', event => {
        if (event.target.classList.contains('copy-btn')) {
          copyToClipboard(event.target.getAttribute('data-copy'), event.target);
        }
      });
    });
    
    function showToast(message, duration = 3000) {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.classList.add('show');
      setTimeout(() => { toast.classList.remove('show'); }, duration);
    }
    
    function copyToClipboard(text, element) {
      navigator.clipboard.writeText(text).then(() => {
        const originalText = element.textContent;
        element.classList.add('copied');
        element.textContent = '已复制 ✓';
        showToast('复制成功！');
        setTimeout(() => { element.classList.remove('copied'); element.textContent = originalText; }, 2000);
      }).catch(err => { console.error('复制失败:', err); showToast('复制失败，请手动复制'); });
    }
    
    function createCopyButton(text) { return `<span class="copy-btn" data-copy="\${text}">\${text}</span>`; }
    
    function isIPAddress(input) {
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const ipv6Regex = /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/;
      const ipv6WithPortRegex = /^\\[[0-9a-fA-F:]+\\]:\\d+$/;
      const ipv4WithPortRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\\d+$/;
      return ipv4Regex.test(input) || ipv6Regex.test(input) || ipv6WithPortRegex.test(input) || ipv4WithPortRegex.test(input);
    }
    
    function preprocessInput(input) { return input ? input.trim().split(' ')[0] : input; }
    
    async function checkProxyIP() {
      if (isChecking) return;
      const proxyipInput = document.getElementById('proxyip');
      const resultDiv = document.getElementById('result');
      const checkBtn = document.getElementById('checkBtn');
      const btnText = checkBtn.querySelector('.btn-text');
      const spinner = checkBtn.querySelector('.loading-spinner');
      const proxyip = preprocessInput(proxyipInput.value);
      
      if (!proxyip) {
        showToast('请输入代理IP地址');
        proxyipInput.focus();
        return;
      }
      
      const currentTimestamp = calculateTimestamp();
      if (currentTimestamp !== pageLoadTimestamp) {
        showToast('页面 TOKEN 已过期，正在刷新...');
        setTimeout(() => window.location.reload(), 1000);
        return;
      }
      
      try { localStorage.setItem('lastProxyIP', proxyip); } catch (error) { console.log('保存历史记录失败:', error); }
      
      isChecking = true;
      checkBtn.disabled = true;
      btnText.style.display = 'none';
      spinner.style.display = 'block';
      resultDiv.classList.remove('show');
      
      try {
        if (isIPAddress(proxyip)) {
          await checkSingleIP(proxyip, resultDiv);
        } else {
          await checkDomain(proxyip, resultDiv);
        }
      } catch (err) {
        resultDiv.innerHTML = `<div class="result-card result-error"><h3>❌ 检测失败</h3><p><strong>错误信息:</strong> \${err.message}</p></div>`;
        resultDiv.classList.add('show');
      } finally {
        isChecking = false;
        checkBtn.disabled = false;
        btnText.style.display = 'block';
        spinner.style.display = 'none';
      }
    }
    
    async function checkSingleIP(proxyip, resultDiv) {
        const data = await checkIPStatus(proxyip);

        if (data.success) {
            const ipInfo = await getIPInfo(data.proxyIP);
            const ipInfoHTML = formatIPInfo(ipInfo);
            const responseTimeHTML = data.responseTime > 0
                ? `
                    <div class="tooltip">
                        <span style="background:var(--success-color);color:white;padding:4px 8px;border-radius:6px;font-weight:600;">\${data.responseTime}ms</span>
                        <span class="tooltiptext">从 <strong>服务器位置 (\${data.country})</strong> 到 ProxyIP 的延迟</span>
                    </div>
                `
                : '';

            resultDiv.innerHTML = `
                <div class="result-card result-success">
                    <h3>✅ ProxyIP 有效</h3>
                    <div style="margin-top:20px;">
                        <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
                            <strong>🌐 ProxyIP 地址:</strong>\${createCopyButton(data.proxyIP)}\${ipInfoHTML}\${responseTimeHTML}
                        </div>
                        <p><strong>🔌 端口:</strong>\${createCopyButton(data.portRemote.toString())}</p>
                    </div>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="result-card result-error">
                    <h3>❌ ProxyIP 无效</h3>
                    <div style="margin-top:20px;">
                        <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
                            <strong>🌐 IP地址:</strong>\${createCopyButton(proxyip)}
                        </div>
                        <p><strong>错误信息:</strong>\${data.message}</p>
                    </div>
                </div>
            `;
        }
        resultDiv.classList.add('show');
    }
    
    async function checkDomain(domain, resultDiv) {
      let portRemote = 443;
      let cleanDomain = domain;
      if (domain.includes(':')) {
          const parts = domain.split(':');
          cleanDomain = parts[0];
          portRemote = parseInt(parts[1]) || 443;
      }
      
      const resolveData = await fetch(`/proxyip/resolve?domain=\${encodeURIComponent(cleanDomain)}&token=\${临时TOKEN}`).then(res => res.json());
      if (!resolveData.success) throw new Error(resolveData.error || '域名解析失败');
      
      const ips = resolveData.ips;
      if (!ips || ips.length === 0) throw new Error('未找到域名对应的IP地址');
      
      ipCheckResults.clear();
      
      // 1. 先用 .map() 生成所有 IP 条目的 HTML 字符串
      const ipItemsHTML = ips.map((ip, index) => {
        return `
          <div class="ip-item" id="ip-item-\${index}">
            <div class="ip-status-line">
              <strong>IP:</strong> \${createCopyButton(ip)}
              <span id="ip-info-\${index}" style="color:var(--text-secondary);"></span>
              <span class="status-icon" id="status-icon-\${index}">🔄</span>
            </div>
          </div>
        `;
      }).join('');

      // 2. 构建主模板，结构更清晰
      resultDiv.innerHTML = `
        <div class="result-card result-warning">
          <h3>🔍 域名解析结果</h3>
          <div style="margin-top:20px;">
            <p><strong>🌐 域名:</strong> \${createCopyButton(cleanDomain)}</p>
            <p><strong>🔌 端口:</strong> \${createCopyButton(portRemote.toString())}</p>
            <p><strong>📋 发现IP:</strong> \${ips.length} 个</p>
          </div>
          <div class="ip-grid" id="ip-grid">
            \${ipItemsHTML}
          </div>
        </div>
      `;
      
      resultDiv.classList.add('show');
      
      // 并发检查所有IP
      const checkPromises = ips.map((ip, index) => checkIPWithIndex(`\${ip}:\${portRemote}`, ip, index));
      await Promise.all(checkPromises);
      
      // 更新最终的检查结果状态
      const validCount = Array.from(ipCheckResults.values()).filter(r => r.success).length;
      const resultCard = resultDiv.querySelector('.result-card');
      if (validCount === ips.length) {
        resultCard.className = 'result-card result-success';
        resultCard.querySelector('h3').innerHTML = '✅ 所有IP均有效';
      } else if (validCount === 0) {
        resultCard.className = 'result-card result-error';
        resultCard.querySelector('h3').innerHTML = '❌ 所有IP均无效';
      } else {
        resultCard.querySelector('h3').innerHTML = `⚠️ 部分IP有效 (\${validCount}/\${ips.length})`;
      }
    }
    
    async function checkIPWithIndex(fullAddress, ip, index) {
      try {
        const result = await checkIPStatus(fullAddress);
        ipCheckResults.set(fullAddress, result);
        const itemElement = document.getElementById(`ip-item-\${index}`);
        const statusIcon = document.getElementById(`status-icon-\${index}`);
        const infoSpan = document.getElementById(`ip-info-\${index}`);

        const ipInfo = await getIPInfo(ip);
        infoSpan.innerHTML = formatIPInfo(ipInfo);

        if (result.success) {
          itemElement.style.borderColor = 'var(--success-color)';
          const responseTimeHTML = result.responseTime > 0 ? `<div class="tooltip"><span style="background:var(--success-color);color:white;padding:2px 6px;border-radius:4px;font-size:12px;">\${result.responseTime}ms</span><span class="tooltiptext">从服务器到此IP的延迟</span></div>` : '';
          statusIcon.innerHTML = responseTimeHTML;
        } else {
          itemElement.style.borderColor = 'var(--error-color)';
          statusIcon.innerHTML = `<div class="tooltip">❌<span class="tooltiptext">\${result.message}</span></div>`;
        }
      } catch (error) {
        console.error('检查IP失败:', error);
        const statusIcon = document.getElementById(`status-icon-\${index}`);
        statusIcon.innerHTML = '❌';
      }
    }
    
    async function getIPInfo(ip) {
      try {
        const cleanIP = ip.replace(/[\\[\\]]/g, '');
        return await fetch(`/proxyip/ip-info?ip=\${encodeURIComponent(cleanIP)}&token=\${临时TOKEN}`).then(res => res.json());
      } catch (error) { return null; }
    }
    
    function formatIPInfo(ipInfo) {
      if (!ipInfo || ipInfo.status !== 'success') return '';
      const country = ipInfo.country || '未知';
      const as = ipInfo.as || '未知';
      return `<span class="tag tag-country">\${country}</span><span class="tag tag-as">\${as}</span>`;
    }
    
    async function checkIPStatus(ip) {
      return await fetch(`/proxyip/check?proxyip=\${encodeURIComponent(ip)}`).then(res => res.json());
    }
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
$timestamp = ceil(time() / (60 * 31));
$临时TOKEN = 双重哈希($hostname . $timestamp . $UA);
$永久TOKEN_final = $永久TOKEN ?: $临时TOKEN;

// --- 路由选择 ---
if (preg_match('#/proxyip/check#', $path)) {
    // API: /proxyip/check
    header('Content-Type: application/json; charset=UTF-8');
    if (!isset($_GET['proxyip'])) {
        http_response_code(400); echo json_encode(['status' => 'error', 'message' => 'Missing proxyip parameter'], JSON_UNESCAPED_UNICODE); exit();
    }
    $result = CheckProxyIP($_GET['proxyip']);
    http_response_code($result['success'] ? 200 : 502);
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

} elseif (preg_match('#/proxyip/resolve#', $path)) {
    // API: /proxyip/resolve
    header('Content-Type: application/json; charset=UTF-8');
    $token = $_GET['token'] ?? null;
    if (!$token || ($token !== $临时TOKEN && $token !== $永久TOKEN_final)) {
         http_response_code(403); echo json_encode(['status' => 'error', 'message' => '域名查询失败: 无效的TOKEN'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit();
    }
    if (!isset($_GET['domain'])) {
        http_response_code(400); echo json_encode(['success' => false, 'error' => 'Missing domain parameter'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit();
    }
    try {
        $ips = resolveDomain($_GET['domain']);
        echo json_encode(['success' => true, 'domain' => $_GET['domain'], 'ips' => $ips], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } catch (Exception $e) {
        http_response_code(500); echo json_encode(['success' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

} elseif (preg_match('#/proxyip/ip-info#', $path)) {
    // API: /proxyip/ip-info
    header('Content-Type: application/json; charset=UTF-8');
    $token = $_GET['token'] ?? null;
    if (!$token || ($token !== $临时TOKEN && $token !== $永久TOKEN_final)) {
         http_response_code(403); echo json_encode(['status' => 'error', 'message' => 'IP查询失败: 无效的TOKEN'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit();
    }
    $ip = $_GET['ip'] ?? $_SERVER['REMOTE_ADDR'];
    $ch = curl_init("http://ip-api.com/json/" . urlencode(trim($ip, '[]')) . "?lang=zh-CN");
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5]);
    $response = curl_exec($ch);
    curl_close($ch);
    $data = json_decode($response, true) ?: ['status' => 'error', 'message' => 'API请求失败'];
    $data['timestamp'] = gmdate('Y-m-d\TH:i:s.v\Z');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

} else {
    // 其他所有 /proxyip/... 的请求，都视为页面请求
    if ($永久TOKEN && ($永久TOKEN !== $临时TOKEN)) {
        nginx();
    } elseif ($URL302) {
        $urls = 整理($URL302);
        if (!empty($urls)) {
            header("Location: " . $urls[array_rand($urls)], true, 302);
            exit();
        }
    } else {
        HTML($hostname, $网站图标, $BEIAN, $临时TOKEN);
    }
}
?>
