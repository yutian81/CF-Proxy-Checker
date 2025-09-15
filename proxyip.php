<?php
// PHP 版本：建议 7.4 或更高
// 依赖扩展：curl, sockets (通常默认启用)
require_once 'config.php';

// --- 1. 读取和配置环境变量 ---
$网站图标 = defined('ICO') && ICO ? ICO : 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
$网站图标_HTML = htmlspecialchars($网站图标, ENT_QUOTES);
$HEAD_FONTS_HTML = defined('HEAD_FONTS') ? HEAD_FONTS : '';
$BEIAN_HTML = defined('BEIAN') && BEIAN ? BEIAN : '© 2025 CF反代检测工具集 By cmliu | Yutian81';
$永久TOKEN = defined('TOKEN') && TOKEN ? TOKEN : null;
$URL302 = defined('URL302') ? URL302 : null;
$IMG = defined('IMG') ? IMG : null;
$IMG_CSS = (!empty($IMG) && $IMG !== '')
    ? 'background-image: url("' . htmlspecialchars($IMG, ENT_QUOTES, 'UTF-8') . '");'
    : 'background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);';

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
    
function 整理($内容) {
    // (此函数保持不变)
    $替换后的内容 = preg_replace('/[ \t|"\'\r\n]+/', ',', $内容);
    $替换后的内容 = preg_replace('/,+/', ',', $替换后的内容);
    $替换后的内容 = trim($替换后的内容, ',');
    return array_filter(explode(',', $替换后的内容));
}
    
function 构建TLS握手_binary() {
    return hex2bin('16030107a30100079f0303af1f4d78be2002cf63e8c727224cf1ee4a8ac89a0ad04bc54cbed5cd7c830880203d8326ae1d1d076ec749df65de6d21dec7371c589056c0a548e31624e121001e0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007361a1a0000000a000c000acaca11ec001d00170018fe0d00ba0000010001fc00206a2fb0535a0a5e565c8a61dcb381bab5636f1502bbd09fe491c66a2d175095370090dd4d770fc5e14f4a0e13cfd919a532d04c62eb4a53f67b1375bf237538cea180470d942bdde74611afe80d70ad25afb1d5f02b2b4eed784bc2420c759a742885f6ca982b25d0fdd7d8f618b7f7bc10172f61d446d8f8a6766f3587abbae805b8ef40fcb819194ac49e91c6c3762775f8dc269b82a21ddccc9f6f43be62323147b411475e47ea2c4efe52ef2cef5c7b32000d00120010040308040401050308050501080606010010000e000c02683208687474702f312e31000b0002010000050005010000000044cd00050003026832001b00030200020017000000230000002d000201010012000000000010000e00000b636861746770742e636f6dff01000100002b0007061a1a03040303003304ef04edcaca00010011ec04c05eac5510812e46c13826d28279b13ce62b6464e01ae1bb6d49640e57fb3191c656c4b0167c246930699d4f467c19d60dacaa86933a49e5c97390c3249db33c1aa59f47205701419461569cb01a22b4378f5f3bb21d952700f250a6156841f2cc952c75517a481112653400913f9ab58982a3f2d0010aba5ae99a2d69f6617a4220cd616de58ccbf5d10c5c68150152b60e2797521573b10413cb7a3aab25409d426a5b64a9f3134e01dc0dd0fc1a650c7aafec00ca4b4dddb64c402252c1c69ca347bb7e49b52b214a7768657a808419173bcbea8aa5a8721f17c82bc6636189b9ee7921faa76103695a638585fe678bcbb8725831900f808863a74c52a1b2caf61f1dec4a9016261c96720c221f45546ce0e93af3276dd090572db778a865a07189ae4f1a64c6dbaa25a5b71316025bd13a6012994257929d199a7d90a59285c75bd4727a8c93484465d62379cd110170073aad2a3fd947087634574315c09a7ccb60c301d59a7c37a330253a994a6857b8556ce0ac3cda4c6fe3855502f344c0c8160313a3732bce289b6bda207301e7b318277331578f370ccbcd3730890b552373afeb162c0cb59790f79559123b2d437308061608a704626233d9f73d18826e27f1c00157b792460eda9b35d48b4515a17c6125bdb96b114503c99e7043b112a398888318b956a012797c8a039a51147b8a58071793c14a3611fb0424e865f48a61cac7c43088c634161cea089921d229e1a370effc5eff2215197541394854a201a6ebf74942226573bb95710454bd27a52d444690837d04611b676269873c50c3406a79077e6606478a841f96f7b076a2230fd34f3eea301b77bf00750c28357a9df5b04f192b9c0bbf4f71891f1842482856b021280143ae74356c5e6a8e3273893086a90daa7a92426d8c370a45e3906994b8fa7a57d66b503745521e40948e83641de2a751b4a836da54f2da413074c3d856c954250b5c8332f1761e616437e527c0840bc57d522529b9259ccac34d7a3888f0aade0a66c392458cc1a698443052413217d29fbb9a1124797638d76100f82807934d58f30fcff33197fc171cfa3b0daa7f729591b1d7389ad476fde2328af74effd946265b3b81fa33066923db476f71babac30b590e05a7ba2b22f86925abca7ef8058c2481278dd9a240c8816bba6b5e6603e30670dffa7e6e3b995b0b18ec404614198a43a07897d84b439878d179c7d6895ac3f42ecb7998d4491060d2b8a5316110830c3f20a3d9a488a85976545917124c1eb6eb7314ea9696712b7bcab1cfd2b66e5a85106b2f651ab4b8a145e18ac41f39a394da9f327c5c92d4a297a0c94d1b8dcc3b111a700ac8d81c45f983ca029fd2887ad4113c7a23badf807c6d0068b4fa7148402aae15cc55971b57669a4840a22301caaec392a6ea6d46dab63890594d41545ebc2267297e3f4146073814bb3239b3e566684293b9732894193e71f3b388228641bb8be6f5847abb9072d269cb40b353b6aa3259ccb7e438d6a37ffa8cc1b7e4911575c41501321769900d19792aa3cfbe58b0aaf91c91d3b63900697279ad6c1aa44897a07d937e0d5826c24439420ca5d8a63630655ce9161e58d286fc885fcd9b19d096080225d16c89939a24aa1e98632d497b5604073b13f65bdfddc1de4b40d2a829b0521010c5f0f241b1ccc759049579db79983434fac2748829b33f001d0020a8e86c9d3958e0257c867e59c8082238a1ea0a9f2cac9e41f9b3cb0294f34b484a4a000100002900eb00c600c0afc8dade37ae62fa550c8aa50660d8e73585636748040b8e01d67161878276b1ec1ee2aff7614889bb6a36d2bdf9ca097ff6d7bf05c4de1d65c2b8db641f1c8dfbd59c9f7e0fed0b8e0394567eda55173d198e9ca40883b291ab4cada1a91ca8306ca1c37e047ebfe12b95164219b06a24711c2182f5e37374d43c668d45a3ca05eda90e90e510e628b4cfa7ae880502dae9a70a8eced26ad4b3c2f05d77f136cfaa622e40eb084dd3eb52e23a9aeff6ae9018100af38acfd1f6ce5d8c53c4a61c547258002120fe93e5c7a5c9c1a04bf06858c4dd52b01875844e15582dd566d03f41133183a0');
}

// 查询服务器本身的地理位置
function getIpInfo_backend($ip) {
    try {
        $ch = curl_init("http://ip-api.com/json/" . urlencode($ip) . "?fields=status,country,countryCode&lang=zh-CN");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3]);
        $response = curl_exec($ch);
        curl_close($ch);
        return json_decode($response, true);
    } catch (Exception $e) {
        return ['status' => 'error', 'message' => $e->getMessage()];
    }
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
        $urls = [
            'A' => "https://1.1.1.1/dns-query?name=" . urlencode($domain) . "&type=A",
            'AAAA' => "https://1.1.1.1/dns-query?name=" . urlencode($domain) . "&type=AAAA"
        ];
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

// --- 3. 主逻辑 & 路由 ---
$path = strtolower(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

// --- Token Generation ---
$hostname = $_SERVER['HTTP_HOST'] ?? 'localhost';
$UA = $_SERVER['HTTP_USER_AGENT'] ?? 'null';
$timestamp = ceil(time() / (60 * 31));
$临时TOKEN = 双重哈希($hostname . $timestamp . $UA);
$临时TOKEN_JS = htmlspecialchars($临时TOKEN);
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
    exit;

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
    exit;

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
    exit;

} else {
    $server_ip = $_SERVER['SERVER_ADDR'] ?? '127.0.0.1';
    $server_info = getIpInfo_backend($server_ip);
    $SERVER_ADD = 'PL';
    if ($server_info && $server_info['status'] === 'success') {
        $SERVER_ADD = $server_info['country'] . ' (' . $server_info['countryCode'] . ')';
    }
    $SERVER_ADD_JS = htmlspecialchars($SERVER_ADD, ENT_QUOTES, 'UTF-8');

    // 其他所有 /proxyip/... 的请求，都视为页面请求
    if ($永久TOKEN && ($永久TOKEN !== $临时TOKEN)) {
        require_once 'nginx_template.php';
    } elseif ($URL302) {
        $urls = 整理($URL302);
        if (!empty($urls)) {
            header("Location: " . $urls[array_rand($urls)], true, 302);
            exit();
        }
    } else {
        require_once 'proxyip_template.php';
    }
}

?>
