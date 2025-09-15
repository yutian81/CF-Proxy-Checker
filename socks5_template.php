<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Socks5/HTTP - 代理检测工具</title>
    <link rel="icon" href="<?php echo $网站图标_HTML; ?>" type="image/x-icon">
    <?php echo $HEAD_FONTS_HTML; ?>
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
      <?php echo $IMG_CSS; ?>
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
    .header-input { display: flex; gap: 10px; flex-grow: 1; max-width: 500px; align-items: center; }
    .header-input input {
        flex-grow: 1; padding: 12px 16px; border: none; border: 2px solid var(--border-color);
        border-radius: var(--border-radius-sm); font-size: 16px; transition: var(--transition);
        line-height: 1.2;
    }
    .header-input input:focus {
        outline: none; border-color: var(--primary-color);
        box-shadow: 0 0 0 4px rgba(52, 152, 219, 0.1);
    }
    .header-input button {
        padding: 12px 24px; border: none; border-radius: var(--border-radius-sm);
         font-size: 16px; font-weight: 600; cursor: pointer; transition: var(--transition); color: white;
        background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
        box-shadow: 0 4px 6px rgba(0,0,0,0.1); line-height: 1.2;
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

    h1 img.emoji,
    h3 img.emoji,
    #checkBtn img.emoji {
        height: 1.2em;
        width: 1.2em;
        vertical-align: middle;
        margin-bottom: 0.1em;
    }
    .footer {
        text-align: center;
        padding: 25px 15px 25px 15px;
        font-size: 14px;
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
        .header-input { width: 100%; flex-direction: column; align-items: stretch; }
        .header-input button { width: 100%; }
        .results-section { grid-template-columns: 1fr; }
        .info-card:first-child { border-bottom: 1px solid var(--border-color); }
    }
    </style>
</head>
<body>
    <a href="https://check.socks5.cmliussss.net" target="_blank" class="github-corner" aria-label="CMLiu Worker 版">
      <svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
    </a>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>🔒 代理检测工具</h1>
                <p>检测代理服务器的出入口信息 (SOCKS5 / HTTP)</p>
            </div>
            <div class="header-input">
                <input type="text" id="proxyInput" placeholder="例如: socks5://user:pass@host:port" />
                <button id="checkBtn" onclick="checkProxy()">🔍 开始检测</button>
            </div>
        </div>
        <div class="results-section">
            <div class="info-card">
                <h3>📥 入口信息</h3>
                <div class="info-content" id="entryInfo">
                    <div class="waiting">请输入代理链接并点击检查</div>
                </div>
            </div>
            <div class="info-card">
                <h3>📤 出口信息</h3>
                <div class="info-content" id="exitInfo">
                    <div class="waiting">请输入代理链接并点击检查</div>
                </div>
            </div>
        </div>
        <div class="footer"><?php echo $BEIAN_HTML; ?></div>
    </div>
      
    <script src="https://twemoji.maxcdn.com/v/latest/twemoji.min.js" crossorigin="anonymous"></script>
    <script>
        const 临时TOKEN = '<?php echo $临时TOKEN_JS; ?>';
        let currentDomainInfo = null;
        let currentProxyTemplate = null;

        // Twemoji 解析，确保所有 emoji 都被渲染成 SVG
        twemoji.parse(document.body, {
            folder: "svg",
            ext: ".svg"
        });
      
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

        // IPv4 简单匹配
        const ipv4Segment = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
        const IPv4Pattern = `(${ipv4Segment}\\.){3}${ipv4Segment}`;
        const ipv4Regex = new RegExp(`^${IPv4Pattern}$`);
        // IPv6 精简版：
        const h16 = "[0-9A-Fa-f]{1,4}";
        const IPv6Full = `(${h16}:){7}${h16}`;
        const IPv6Compressed = `(${h16}(:${h16})*)?::(${h16}(:${h16})*)?`;
        const ipv6Regex = new RegExp(`^(${IPv6Full}|${IPv6Compressed})(%.+)?$`);
        // 统一函数
        const isIPAddress = host => ipv4Regex.test(host) || ipv6Regex.test(host);      
        
        function replaceHostInProxy(proxyUrl, newHost) {
            const [protocol, rest] = proxyUrl.split('://');
            let authPart = rest.includes('@') ? rest.substring(0, rest.lastIndexOf('@') + 1) : '';
            let hostPart = rest.includes('@') ? rest.substring(rest.lastIndexOf('@') + 1) : rest;
            const port = hostPart.includes(':') ? hostPart.substring(hostPart.lastIndexOf(':') + 1) : '';
            const processedNewHost = newHost.includes(':') && !newHost.startsWith('[') ? `[${newHost}]` : newHost;
            return `${protocol}://${authPart}${processedNewHost}:${port}`;
        }
        
        function formatInfoDisplay(data, containerId, showIPSelector = false) {
            const container = document.getElementById(containerId);
            if (!data || data.error) {
                container.innerHTML = '<div class="error">数据获取失败</div>';
                return;
            }
            
            const ipDisplay = showIPSelector && currentDomainInfo && currentDomainInfo.all_ips.length > 1
                ? `<div class="ip-selector">
                        <span class="ip-text">${data.resolved_ip || data.ip || 'N/A'}</span>
                        <button class="more-ip-btn" onclick="toggleIPDropdown(event)">${currentDomainInfo.all_ips.length} IPs</button>
                        <div class="ip-value-container">
                            <div class="ip-dropdown" id="ipDropdown">
                                ${currentDomainInfo.all_ips.map(ip => `<div class="ip-option ${ip === (data.resolved_ip || data.ip) ? 'active' : ''}" onclick="selectIP('${ip}')">${ip}</div>`).join('')}
                            </div>
                        </div>
                   </div>`
                : (data.resolved_ip || data.ip || 'N/A');

            container.innerHTML = `
                <div class="info-item"><span class="info-label">IP 地址:</span><span class="info-value">${ipDisplay}</span></div>
                <div class="info-item"><span class="info-label">ASN:</span><span class="info-value">${data.asn?.asn ? 'AS' + data.asn.asn : 'N/A'}</span></div>
                <div class="info-item"><span class="info-label">组织:</span><span class="info-value">${data.asn?.org || 'N/A'}</span></div>
                <div class="info-item"><span class="info-label">位置:</span><span class="info-value">${data.location?.city || 'N/A'}, ${data.location?.country_code || 'N/A'}</span></div>
                <div class="info-item"><span class="info-label">数据中心:</span><span class="info-value"><span class="${data.is_datacenter ? 'status-yes' : 'status-no'}">${data.is_datacenter ? '是' : '否'}</span></span></div>
                <div class="info-item"><span class="info-label">代理/VPN:</span><span class="info-value"><span class="${data.is_proxy || data.is_vpn ? 'status-yes' : 'status-no'}">${data.is_proxy || data.is_vpn ? '是' : '否'}</span></span></div>
                <div class="info-item"><span class="info-label">Tor 节点:</span><span class="info-value"><span class="${data.is_tor ? 'status-yes' : 'status-no'}">${data.is_tor ? '是' : '否'}</span></span></div>
                <div class="info-item"><span class="info-label">滥用风险:</span><span class="info-value"><span class="${data.is_abuser ? 'status-yes' : 'status-no'}">${data.is_abuser ? '是' : '否'}</span></span></div>
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
                entryInfo.innerHTML = `<div class="error">${error.message}</div>`;
                exitInfo.innerHTML = `<div class="error">${error.message}</div>`;
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
                const response = await fetch(`/socks5/ip-info?ip=${encodeURIComponent(host)}&token=${临时TOKEN}`);
                const data = await response.json();
                if (!data.ips) throw new Error(`域名解析失败: ${data.message || '未知错误'}`);
                currentDomainInfo = { all_ips: data.ips, domain: host };
                targetIP = data.resolved_ip;
                targetProxyUrl = replaceHostInProxy(proxyUrl, targetIP);
            }
            
            entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>获取入口信息...</div>';
            exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>检测代理中...</div>';

            const [entryResult, exitResult] = await Promise.allSettled([
                fetch(`/socks5/ip-info?ip=${encodeURIComponent(targetIP)}&token=${临时TOKEN}`).then(res => res.json()),
                fetch(`/socks5/check?proxy=${encodeURIComponent(targetProxyUrl)}`).then(res => res.json())
            ]);
            
            if (entryResult.status === 'fulfilled') {
                formatInfoDisplay(entryResult.value, 'entryInfo', !!currentDomainInfo);
            } else {
                entryInfo.innerHTML = '<div class="error">获取入口信息失败</div>';
            }
            
            if (exitResult.status === 'fulfilled') {
                if (!exitResult.value.success) {
                    exitInfo.innerHTML = `<div class="error">代理检测失败: ${exitResult.value.error || '请检查代理链接'}</div>`;
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
