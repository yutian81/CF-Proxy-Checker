# CF-Proxy-Checker
这是一个部署在 Cloudflare Workers 上的高性能、多功能代理检测套件。它整合了多个强大的网络检测工具，提供统一的网页界面和标准化的API接口

**从 cm 的 proxyip、socks6、nat64 反代检测整合而来**

----

## ✨ 项目特点

- **多功能合一**: 集成了 **ProxyIP**、**SOCKS5/HTTP 代理** 和 **NAT64/DNS64** 三大检测模块。
- **高性能**: 基于 Cloudflare 的全球边缘网络，提供极低的延迟和高并发处理能力。
- **优雅的界面**: 每个工具都拥有独立、美观且响应式的前端页面，并提供一个精美的导航主页。
- **标准化 API**: 为所有检测功能提供了一致的 RESTful API 接口，方便自动化和集成。
- **高度可定制**: 支持通过环境变量自定义网站图标、背景、页脚内容，并可设置密码保护或全局跳转。
- **零依赖**: 无需外部数据库或缓存服务，部署简单。
    
## 🚀 部署方法

本项目支持通过 Wrangler CLI 轻松部署。推荐采用手动设置环境变量的方式，以确保安全性。

- 给本项目点 ⭐ 并 fork
- 登录 CF 账号，创建一个worker
- 链接 github 账户，选择 fork 的本项目
- 点击部署
- 进入项目设置，按需求配置环境变量（均为可选，也可不设置）

| **变量名**    | **是否必须** | **说明**                                          | **示例值**                                                                |
| ------------ | ----------- | ------------------------------------------------- | ------------------------------------------------------------------------- |
| `TOKEN`      | 可选       | 为整个应用设置一个访问密码。设置后，访问主页或各工具页面都需要在URL后添加 `?token=您的密码` | `my-secret-password-123`                 |
| `ICO_URL`    | 可选       | 自定义网站的 favicon 图标地址。                       | `https://example.com/favicon.ico`                               |
| `IMG_URL`    | 可选       | 自定义主页和Socks5页面的背景图片地址。                 | `https://images.unsplash.com/photo-1513542789411-b6a5abb4c291` |
| `BEIAN_HTML` | 可选       | 自定义所有页面底部的页脚HTML内容，例如备案信息或版权声明。 | `见下文示例` |
| `URL302`     | 可选       | 设置一个全局302跳转地址。一旦设置，所有访问都会被重定向到此URL，可用于临时下线或域名迁移。     | `https://new-domain.com`              |

```html
/* BEIAN_HTML 变量示例值 */
<p>
    <a href="./">© 2025 CF反代检测工具集</a> | 基于 CF Workers 构建 |
    <a href="https://github.com/cmliu" rel="noopener noreferrer">原作者 CMliu</a> |
    <a href="https://github.com/yutian81" rel="noopener noreferrer">整合 Yutian81</a> |
    <a href="https://blog.811520.xyz" rel="noopener noreferrer">QingYun Blog</a>
</p>
```

- 绑定自定义域名

## 📚 API 调用指南

所有 API 的基础路径都是您的 Worker 域名，例如：`https://your-worker.your-subdomain.workers.dev`

### 1. ProxyIP 模块

#### 检查 ProxyIP

- **路径**: `/proxyip/check`
- **方法**: `GET`
- **参数**: `proxyip` (必须) - 要检测的 IP 地址和端口。
- **示例**: `GET /proxyip/check?proxyip=1.2.3.4:443`
- **响应**: 返回一个 JSON 对象，包含检测结果、响应时间、国家等信息。
    
#### 解析域名
- **路径**: `/proxyip/resolve`
- **方法**: `GET`
- **参数**:
    - `domain` (必须) - 要解析的域名。  
    - `token` (必须) - 访问令牌（后端动态生成，由前端页面自动提供）。 
- **示例**: `GET /proxyip/resolve?domain=example.com&token=...`
- **响应**: 返回一个 JSON 对象，包含解析出的所有 IP 地址。
    
#### 查询 IP 信息

- **路径**: `/proxyip/ip-info`
- **方法**: `GET`
- **参数**:
    - `ip` (必须) - 要查询的 IP 地址。
    - `token` (必须) - 访问令牌（后端动态生成，由前端页面自动提供）。     
- **示例**: `GET /proxyip/ip-info?ip=8.8.8.8&token=...` 
- **响应**: 返回 `ip-api.com` 提供的详细地理位置和 ASN 信息。
    
### 2. SOCKS5/HTTP 模块

#### 检查代理
- **路径**: `/socks5/check`
- **方法**: `GET`
- **参数**: `proxy` (必须) - 完整的代理 URL，支持 `socks5://` 和 `http://` 协议。
- **示例**: `GET /socks5/check?proxy=socks5://user:pass@1.2.3.4:1080`
- **响应**: 返回代理出口 IP 的详细地理位置和 ASN 信息。
    
#### 查询 IP 信息
- **路径**: `/socks5/ip-info`
- **方法**: `GET`
- **参数**:
    - `ip` (必须) - 要查询的 IP 地址或域名。
    - `token` (必须) - 访问令牌（后端动态生成，由前端页面自动提供）。
- **示例**: `GET /socks5/ip-info?ip=google.com&token=...`
- **响应**: 返回 IP 的详细信息。如果输入是域名，会自动解析并附加 DNS 信息。
    
### 3. NAT64/DNS64 模块

#### 检查 NAT64/DNS64

- **路径**: `/nat64/check` 
- **方法**: `GET`
- **参数**:
    - `nat64` (可选) - 自定义的 DNS64 服务器或 NAT64 前缀。默认为 `dns64.cmliussss.net`。
    - `host` (可选) - 用于测试的目标主机。默认为 `cf.hw.090227.xyz`。  
- **示例**: `GET /nat64/check?nat64=2001:67c:2960:6464::/96`
- **响应**: 返回检测结果，包括合成的 IPv6 地址、NAT64 前缀以及 `/cdn-cgi/trace` 的信息。
    
#### 查询 IP 信息
- **路径**: `/nat64/ip-info`
- **方法**: `GET`
- **参数**:
    - `ip` (必须) - 要查询的 IP 地址或域名。
    - `token` (必须) - 访问令牌（后端动态生成，由前端页面自动提供）。
- **示例**: `GET /nat64/ip-info?ip=1.1.1.1&token=...`
- **响应**: 返回 IP 的详细信息。如果输入是域名，会自动解析并附加 DNS 信息。
