<!DOCTYPE html>
<html lang="zh-CN">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check ProxyIP - 代理IP检测服务</title>
    <link rel="icon" href="<?php echo $网站图标_HTML; ?>" type="image/x-icon">
    <?php echo $HEAD_FONTS_HTML; ?>
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
            <?php echo $IMG_CSS; ?>
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
        .footer a { color: rgba(255,255,255,0.9); text-decoration: none; position: relative; padding-bottom: 2px; transition: color 0.3s; }
        .footer a::after { content: ''; position: absolute; bottom: 0; left: 0; width: 0; height: 1px; background: white; transition: width 0.3s ease; }
        .footer a:hover::after { width: 100%; }
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
      
       .form-label img.emoji,
       .code-block img.emoji,
       h2 img.emoji,
       h3 img.emoji,
       #checkBtn img.emoji {
           height: 1.2em;
           width: 1.2em;
           vertical-align: middle;
           margin-bottom: 0.1em;
        }
      
        @keyframes fadeInDown{from{opacity:0;transform:translateY(-30px)}to{opacity:1;transform:translateY(0)}}
        @keyframes fadeInUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
        @media (max-width: 768px) {
            .container { margin-top: 20px; }
            .card, .api-docs { padding: 24px; }
            .input-group { flex-direction: column; align-items: stretch; }
            .input-wrapper { min-width: 0; }
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
    <a href="https://check.proxyip.cmliussss.net" target="_blank" class="github-corner" aria-label="CMLiu Worker 版">
        <svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
    </a>

    <div class="container">
        <header class="header">
        <h1 class="main-title">Check ProxyIP</h1>
        </header>

        <div class="card">
        <div class="form-section">
            <label for="proxyip" class="form-label">🌐 输入 ProxyIP 地址</label>
            <div class="input-group">
            <div class="input-wrapper">
                <input type="text" id="proxyip" class="form-input" placeholder="例如: 1.2.3.4:443 或 example.com" autocomplete="off">
            </div>
            <button id="checkBtn" class="btn btn-primary" onclick="checkProxyIP()">
                <span class="btn-text">🔍 开始检测</span>
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
        <div class="footer"><?php echo $BEIAN_HTML; ?></div>
    </div>

    <div id="toast" class="toast"></div>

    <script src="https://twemoji.maxcdn.com/v/latest/twemoji.min.js" crossorigin="anonymous"></script>
    <script>
    const 临时TOKEN = '<?php echo $临时TOKEN_JS; ?>';
    const SERVER_ADD = '<?php echo $SERVER_ADD_JS; ?>';
    let isChecking = false;
    const ipCheckResults = new Map();
    let pageLoadTimestamp;

    // Twemoji 解析，确保所有 emoji 都被渲染成 SVG
    twemoji.parse(document.body, {
        folder: "svg",
        ext: ".svg"
    });      
      
    function calculateTimestamp() {
      const currentDate = new Date();
      return Math.ceil(currentDate.getTime() / (1000 * 60 * 13));
    }

    function isValidProxyIPFormat(input) {
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}]?$/;
        const withPortRegex = /^.+:\d+$/;
        const tpPortRegex = /^.+.tp\d+./;
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
    
    function createCopyButton(text) { return `<span class="copy-btn" data-copy="${text}">${text}</span>`; }
    
    function isIPAddress(input) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}]?$/;
        const ipv6WithPortRegex = /^\[[0-9a-fA-F:]+\]:\d+$/;
        const ipv4WithPortRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d+$/;
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
        resultDiv.innerHTML = `<div class="result-card result-error"><h3>❌ 检测失败</h3><p><strong>错误信息:</strong> ${err.message}</p></div>`;
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
                        <span style="background:var(--success-color);color:white;padding:4px 8px;border-radius:6px;font-weight:600;">${data.responseTime}ms</span>
                        <span class="tooltiptext">从 <strong>服务器位置 ${SERVER_ADD}</strong> 到 ProxyIP 的延迟</span>
                    </div>`
                : '';

            resultDiv.innerHTML = `
                <div class="result-card result-success">
                    <h3>✅ ProxyIP 有效</h3>
                    <div style="margin-top:20px;">
                        <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
                            <strong>🌐 ProxyIP 地址:</strong>${createCopyButton(data.proxyIP)}${ipInfoHTML}${responseTimeHTML}
                        </div>
                        <p><strong>🔌 端口:</strong>${createCopyButton(data.portRemote.toString())}</p>
                    </div>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="result-card result-error">
                    <h3>❌ ProxyIP 无效</h3>
                    <div style="margin-top:20px;">
                        <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
                            <strong>🌐 IP地址:</strong>${createCopyButton(proxyip)}
                        </div>
                        <p><strong>错误信息:</strong>${data.message}</p>
                    </div>
                </div>
            `;
        }
        resultDiv.classList.add('show');
    }
    
    async function checkDomain(domain, resultDiv) {
      let portRemote = 443;
      let cleanDomain = domain;
      const specialPortRegex = /(?:tp|p)(\d+)/i;
      const match = domain.match(specialPortRegex);
      
        if (match) {
            portRemote = parseInt(match[1], 10);
        } else if (domain.includes(':')) {
            const parts = domain.split(':');
            portRemote = parseInt(parts[1]) || 443;
        }
      
        if (cleanDomain.includes(':')) {
            cleanDomain = cleanDomain.split(':')[0];
        }
      
      const resolveData = await fetch(`/proxyip/resolve?domain=${encodeURIComponent(cleanDomain)}&token=${临时TOKEN}`).then(res => res.json());
      if (!resolveData.success) throw new Error(resolveData.error || '域名解析失败');
      
      const ips = resolveData.ips;
      if (!ips || ips.length === 0) throw new Error('未找到域名对应的IP地址');
      
      ipCheckResults.clear();
      
      // 1. 先用 .map() 生成所有 IP 条目的 HTML 字符串
      const ipItemsHTML = ips.map((ip, index) => {
        return `
          <div class="ip-item" id="ip-item-${index}">
            <div class="ip-status-line">
              <strong>IP:</strong> ${createCopyButton(ip)}
              <span id="ip-info-${index}" style="color:var(--text-secondary);"></span>
              <span class="status-icon" id="status-icon-${index}">🔄</span>
            </div>
          </div>
        `;
      }).join('');

      // 2. 构建主模板，结构更清晰
      resultDiv.innerHTML = `
        <div class="result-card result-warning">
          <h3>🔍 域名解析结果</h3>
          <div style="margin-top:20px;">
            <p><strong>🌐 域名:</strong> ${createCopyButton(cleanDomain)}</p>
            <p><strong>🔌 端口:</strong> ${createCopyButton(portRemote.toString())}</p>
            <p><strong>📋 发现IP:</strong> ${ips.length} 个</p>
          </div>
          <div class="ip-grid" id="ip-grid">
            ${ipItemsHTML}
          </div>
        </div>
      `;
      
      resultDiv.classList.add('show');
      
      // 并发检查所有IP
      const checkPromises = ips.map((ip, index) => checkIPWithIndex(`${ip}:${portRemote}`, ip, index));
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
        resultCard.querySelector('h3').innerHTML = `⚠️ 部分IP有效 (${validCount}/${ips.length})`;
      }
    }
    
    async function checkIPWithIndex(fullAddress, ip, index) {
      try {
        const result = await checkIPStatus(fullAddress);
        ipCheckResults.set(fullAddress, result);
        const itemElement = document.getElementById(`ip-item-${index}`);
        const statusIcon = document.getElementById(`status-icon-${index}`);
        const infoSpan = document.getElementById(`ip-info-${index}`);

        const ipInfo = await getIPInfo(ip);
        infoSpan.innerHTML = formatIPInfo(ipInfo);

        if (result.success) {
          itemElement.style.borderColor = 'var(--success-color)';
          const responseTimeHTML = result.responseTime > 0
              ? `
              <div class="tooltip">
                  <span style="background: var(--success-color); color: white; padding: 2px 6px; border-radius: 4px; font-size: 12px;">${result.responseTime}ms</span>
                  <span class="tooltiptext">从 <strong>服务器位置 ${SERVER_ADD}</strong> 到此 IP 的延迟</span>
              </div>`
              : '';
          statusIcon.innerHTML = responseTimeHTML;
        } else {
          itemElement.style.borderColor = 'var(--error-color)';
          statusIcon.innerHTML = `<div class="tooltip">❌<span class="tooltiptext">${result.message}</span></div>`;
        }
      } catch (error) {
        console.error('检查IP失败:', error);
        const statusIcon = document.getElementById(`status-icon-${index}`);
        statusIcon.innerHTML = '❌';
      }
    }
    
    async function getIPInfo(ip) {
      try {
        const cleanIP = ip.replace(/[\\[\\]]/g, '');
        return await fetch(`/proxyip/ip-info?ip=${encodeURIComponent(cleanIP)}&token=${临时TOKEN}`).then(res => res.json());
      } catch (error) { return null; }
    }
    
    function formatIPInfo(ipInfo) {
      if (!ipInfo || ipInfo.status !== 'success') return '';
      const country = ipInfo.country || '未知';
      const as = ipInfo.as || '未知';
      return `<span class="tag tag-country">${country}</span><span class="tag tag-as">${as}</span>`;
    }
    
    async function checkIPStatus(ip) {
      return await fetch(`/proxyip/check?proxyip=${encodeURIComponent(ip)}`).then(res => res.json());
    }
  </script>
    </body>
</html>
