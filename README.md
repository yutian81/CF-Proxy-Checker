# CF-Proxy-Checker
这是一个部署在 PHP 服务器上的高性能、多功能代理检测套件。它整合了多个强大的网络检测工具，提供统一的网页界面和标准化的API接口

**从 cm 的 [proxyip](https://github.com/cmliu/CF-Workers-CheckProxyIP)、[socks5](https://github.com/cmliu/CF-Workers-CheckSocks5)、[nat64](https://github.com/cmliu/CF-Workers-CheckNAT64) 反代检测整合而来**

----

## ✨ 项目特点

- **多功能合一**: 集成了 **ProxyIP**、**SOCKS5/HTTP 代理** 和 **NAT64/DNS64** 三大检测模块。
- **高性能**: 基于 php，不受CF worker CPU挂钟时间限制，高并发处理能力。
- **优雅的界面**: 每个工具都拥有独立、美观且响应式的前端页面，并提供一个精美的导航主页。
- **标准化 API**: 为所有检测功能提供了一致的 RESTful API 接口，方便自动化和集成。
- **高度可定制**: 支持通过环境变量自定义网站图标、背景、页脚内容，并可设置密码保护或全局跳转。
- **零依赖**: 无需外部数据库或缓存服务，部署简单。
    
## 🚀 部署方法

- 上传全部文件到 php 服务器，若服务器没有 ipv6，则本工具也不支持 ipv6 的检测
- 环境变量在 `config.php` 文件中修改

| **变量名**    | **是否必须** | **说明**                                          | **示例值**                                                                |
| ------------ | ----------- | ------------------------------------------------- | ------------------------------------------------------------------------- |
| `TOKEN`      | 可选       | 为整个应用设置一个访问密码。设置后，访问主页或各工具页面都需要在URL后添加 `?token=您的密码` | `my-secret-password-123`                 |
| `ICO`    | 可选       | 自定义网站的 favicon 图标地址。                       | `https://example.com/favicon.ico`                               |
| `IMG`    | 可选       | 背景图片地址，支持多个背景图随机切换，地址之间用`,`分隔  | `https://images.unsplash.com/photo-1513542789411-b6a5abb4c291` |
| `BEIAN` | 可选       | 自定义所有页面底部的页脚HTML内容，例如备案信息或版权声明。 | 见 `config.php` 中示例 |
| `URL302`     | 可选       | 设置一个全局302跳转地址。一旦设置，所有访问都会被重定向到此URL，可用于临时下线或域名迁移。     | `https://new-domain.com`              |

## 📚 API 调用指南

> **所有 API 的基础路径都基于根地址，如 `https://your-subdomain.serv00.net`**

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
- **参数**: `proxy` (必须) - 完整的代理 URL，支持 `socks5://` 和 `http://` 协议。此参数也接受 `socks5` 或 `http` 作为别名。
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
    - `nat64` 或 `dns64` (可选) - 自定义的 DNS64 服务器或 NAT64 前缀。代码会优先使用 dns64 参数, 默认为 `dns64.cmliussss.net`。
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
