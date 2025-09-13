<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="高性能，实时检测，专业分析，一站式检测各类反代CF服务的可用性，确保您的网络连接畅通无阻">
    <title>CF反代可用性检测工具集</title>
    <link rel="icon" href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #3498db;
            --primary-dark: #2980b9;
            --secondary-color: #1abc9c;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --error-color: #e74c3c;
            --bg-primary: rgba(255, 255, 255, 0.85);
            --bg-secondary: rgba(248, 249, 250, 0.8);
            --bg-tertiary: rgba(233, 236, 239, 0.65);
            --text-primary: #2c3e50;
            --text-secondary: #4a5568;
            --text-light: #718096;
            --border-color: rgba(222, 226, 230, 0.6);
            --shadow-sm: 0 2px 4px rgba(0,0,0,0.08);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.12);
            --shadow-lg: 0 10px 25px rgba(0,0,0,0.15);
            --border-radius: 16px;
            --border-radius-sm: 10px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Segoe UI Emoji', 'Apple Color Emoji', sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            position: relative;
            overflow-x: hidden;
            padding: 20px;
        }
        
        body::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('https://images.unsplash.com/photo-1513542789411-b6a5abb4c291?q=80&w=2940') center/cover no-repeat;
            filter: blur(8px) brightness(0.8);
            z-index: -1;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            animation: fadeInDown 0.8s ease-out;
            padding: 30px 0;
            position: relative;
        }
        
        .main-title {
            font-size: clamp(2.2rem, 4.5vw, 3.5rem);
            font-weight: 800;
            color: white;
            margin-bottom: 16px;
            text-shadow: 0 4px 12px rgba(0,0,0,0.25);
            letter-spacing: -0.5px;
        }
        
        .subtitle {
            font-size: 1.2rem;
            color: rgba(255,255,255,0.92);
            font-weight: 400;
            margin-bottom: 8px;
            max-width: 700px;
            margin: 0 auto 16px;
        }
        
        .badge {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            backdrop-filter: blur(10px);
            padding: 8px 24px;
            border-radius: 50px;
            color: white;
            font-size: 1rem;
            font-weight: 500;
            border: 1px solid rgba(255,255,255,0.3);
            margin-top: 10px;
        }
        
        .card {
            background: var(--bg-primary);
            border-radius: var(--border-radius);
            padding: 36px;
            box-shadow: var(--shadow-lg);
            margin-bottom: 32px;
            border: 1px solid var(--border-color);
            transition: var(--transition);
            animation: fadeInUp 0.8s ease-out;
            backdrop-filter: blur(16px);
            position: relative;
            overflow: hidden;
        }
        
        .card::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 5px;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
            border-radius: var(--border-radius) var(--border-radius) 0 0;
        }
        
        .card:hover {
            transform: translateY(-6px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
        }
        
        .btn {
            padding: 10px 28px;
            border: none;
            border-radius: var(--border-radius-sm);
            font-size: 16px;
            font-weight: 600;
            font-family: inherit;
            cursor: pointer;
            transition: var(--transition);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            min-width: 140px;
            position: relative;
            overflow: hidden;
            width: 100%;
            margin-top: auto;
            letter-spacing: 0.5px;
        }
        
        .btn::before {
            content: "";
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.6s;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: white;
            box-shadow: var(--shadow-md);
        }
        
        .btn-primary:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 25px rgba(52, 152, 219, 0.4);
        }
        
        .btn-primary:active {
            transform: translateY(0);
        }

        .tool-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 28px;
            margin-top: 20px;
        }
        
        .tool-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius-sm);
            padding: 32px 24px;
            transition: var(--transition);
            position: relative;
            text-align: center;
            box-shadow: var(--shadow-sm);
            display: flex;
            flex-direction: column;
            height: 100%;
        }
        
        .tool-card:hover {
            transform: translateY(-8px);
            box-shadow: var(--shadow-lg);
            background: rgba(255, 255, 255, 0.95);
        }
        
        .tool-icon {
          height: 70px;
          margin-bottom: 24px;
          display: flex;
          justify-content: center;
          align-items: center;
          position: relative;
        }
       
        .tool-icon img.emoji {
          width: 70px;
          height: 70px;
        }
      
        h3 img.emoji, .toast img.emoji {
          height: 1.1em;
          width: 1.1em;
          vertical-align: -0.15em;
        }
 
         .btn-icon img.emoji {
          height: 1.3em;
          width: 1.3em;
          vertical-align: -0.35em;
        }
      
        .tool-title {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 16px;
            color: var(--text-primary);
        }
        
        .tool-desc {
            color: var(--text-secondary);
            margin-bottom: 24px;
            min-height: 72px;
            font-size: 1.05rem;
            line-height: 1.7;
        }
        
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 24px;
        }
        
        .feature-card {
            background: var(--bg-tertiary);
            padding: 24px;
            border-radius: var(--border-radius-sm);
            transition: var(--transition);
            backdrop-filter: blur(5px);
        }
        
        .feature-card:hover {
            transform: translateY(-4px);
            background: rgba(255, 255, 255, 0.9);
            box-shadow: var(--shadow-sm);
        }
        
        .feature-card h3 {
            color: var(--primary-color);
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.25rem;
        }
        
        .feature-card p {
            color: var(--text-secondary);
            font-size: 1.05rem;
            line-height: 1.6;
        }
        
        .footer {
            text-align: center;
            padding: 30px 20px 20px;
            color: rgba(255,255,255,0.85);
            font-size: 15px;
            margin-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.15);
            backdrop-filter: blur(5px);
            border-radius: 0 0 var(--border-radius) var(--border-radius);
        }
        
        .footer a {
            color: rgba(255,255,255,0.92);
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
            background: white;
            transition: width 0.3s ease;
        }
        
        .footer a:hover::after {
            width: 100%;
        }
        
        .footer a:hover {
            color: white;
        }
        
        .section-title {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 28px;
            position: relative;
            padding-bottom: 16px;
            color: var(--text-primary);
        }
        
        .section-title::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 70px;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
            border-radius: 2px;
        }
   
        @keyframes fadeInDown {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes float {
            0% {
                transform: translateY(0px);
            }
            50% {
                transform: translateY(-12px);
            }
            100% {
                transform: translateY(0px);
            }
        }
       
        @media (max-width: 768px) {
            .container {
                padding: 0 16px;
            }
            
            .card {
                padding: 24px 18px;
                margin-bottom: 24px;
            }

            .main-title {
                font-size: 2.2rem;
            }
            
            .tool-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            
            .features-grid {
                grid-template-columns: 1fr;
            }
        }
        
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--text-primary);
            color: white;
            padding: 16px 24px;
            border-radius: var(--border-radius-sm);
            box-shadow: var(--shadow-lg);
            transform: translateY(100px);
            opacity: 0;
            transition: var(--transition);
            z-index: 1000;
            backdrop-filter: blur(10px);
            background: rgba(44, 62, 80, 0.9);
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .toast.show {
            transform: translateY(0);
            opacity: 1;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1 class="main-title">CF反代可用性检测工具集</h1>
            <p class="subtitle">一站式检测各类反代CF服务的可用性，确保您的网络连接畅通无阻</p>
            <span class="badge">高性能 · 实时检测 · 专业分析</span>
        </header>

        <div class="card">
            <div class="tool-grid">
                <div class="tool-card">
                    <div class="tool-icon">🌐</div>
                    <h3 class="tool-title">ProxyIP 可用性检测</h3>
                    <p class="tool-desc">检测 ProxyIP 的连接性、响应时间和可用性，确保您的代理服务稳定可靠</p>
                    <a href="/proxyip" class="btn btn-primary">
                        <span class="btn-icon">🔍</span> 立即检测
                    </a>
                </div>
                
                <div class="tool-card">
                    <div class="tool-icon">🔒</div>
                    <h3 class="tool-title">Socks5/HTTP 代理检测</h3>
                    <p class="tool-desc">全面测试Socks5和HTTP代理的连通性、认证机制和传输性能</p>
                    <a href="/socks5" class="btn btn-primary">
                        <span class="btn-icon">🔍</span> 立即检测
                    </a>
                </div>
                
                <div class="tool-card">
                    <div class="tool-icon">🔄</div>
                    <h3 class="tool-title">DNS64/NAT64 可用性检测</h3>
                    <p class="tool-desc">验证DNS64和NAT64转换服务的可用性及IPv6转换效率</p>
                    <a href="/nat64" class="btn btn-primary">
                        <span class="btn-icon">🔍</span> 立即检测
                    </a>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2 class="section-title">为什么选择这个检测工具？</h2>
            
            <div class="features-grid">
                <div class="feature-card">
                    <h3>⚡ 高性能检测</h3>
                    <p>基于Cloudflare Workers构建，全球分布式节点轻松应对高并发检测需求</p>
                </div>
                
                <div class="feature-card">
                    <h3>📊 大佬出品</h3>
                    <p>由业界知名大佬CMLiu倾力打造，实现反代新方式，定义CF EDT项目技术新标准</p>
                </div>
                
                <div class="feature-card">
                    <h3>🔐 安全可靠</h3>
                    <p>所有检测过程均不存储数据，端到端加密传输，确保隐私安全和检测结果可靠性</p>
                </div>
                
                <div class="feature-card">
                    <h3>🌍 全球覆盖</h3>
                    <p>支持全球多个检测节点，准确反映不同地区访问代理服务的性能和可用性情况</p>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>© 2025 网络代理检测工具集 | 基于 PHP 构建 |
                <a href="https://github.com/cmliu">原作者 CMliu</a> |
                <a href="https://github.com/yutian81">修改 Yutian81</a> |
                <a href="https://blog.811520.xyz">QingYun Blog</a>
            </p>
        </div>
    </div>

    <div id="toast" class="toast"></div>

    <script src="https://twemoji.maxcdn.com/v/latest/twemoji.min.js" crossorigin="anonymous"></script>  
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // 工具卡片动画
            const toolCards = document.querySelectorAll('.tool-card');
            toolCards.forEach((card, index) => {
                card.style.animation = `fadeInUp 0.5s ease-out ${index * 0.2}s both`;
                
                // 添加浮动效果
                card.addEventListener('mouseenter', () => {
                    card.style.animation = 'float 3s ease-in-out infinite';
                });
                
                card.addEventListener('mouseleave', () => {
                    card.style.animation = '';
                });
            });
            
            // 特性卡片动画
            const featureCards = document.querySelectorAll('.feature-card');
            featureCards.forEach((card, index) => {
                card.style.animation = `fadeInUp 0.5s ease-out ${index * 0.15}s both`;
            });
            
            // 显示欢迎消息
            setTimeout(() => {
                showToast('✨ 欢迎使用网络代理检测工具集！');
            }, 1000);

            // Twemoji 解析，确保所有 emoji 都被渲染成 SVG
            twemoji.parse(document.body, {
                folder: "svg", // 用 SVG（更清晰）
                ext: ".svg"
            });
        });
        
        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.classList.add('show');
            
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }
    </script>
</body>
</html>
