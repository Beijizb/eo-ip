# IP优化系统 - Cloudflare Workers 版本

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Cloudflare%20Workers-orange.svg)
![Language](https://img.shields.io/badge/language-JavaScript-yellow.svg)
![Status](https://img.shields.io/badge/status-stable-green.svg)

一个基于 Cloudflare Workers 的智能 IP 优化系统，可以自动获取优选 IP 并更新 DNS 记录，支持多种通知方式。

## 🎯 项目特点

- **🚀 零配置部署**：单文件上传即可运行，无需复杂配置
- **🔄 全自动化**：定时获取优选IP并自动更新DNS记录
- **🌐 多数据源**：支持微测网等多个IP数据源
- **📱 多通知渠道**：支持息知、Telegram等通知方式
- **🛡️ 安全可靠**：双重认证机制，数据加密存储
- **💻 现代化界面**：基于React的响应式Web管理界面

## 🌟 主要功能

 - **智能 IP 获取**：自动测试并选择最优 IP，确保访问速度稳定
 - **自动 DNS 更新**：支持 Cloudflare DNS A 记录自动更新，可自定义 TTL
 - **多种通知方式**：支持 Telegram Bot、息知等多种渠道，及时获取更新
 - **Web 管理界面**：基于 React 的响应式界面，可在浏览器实时调整配置
 - **定时任务**：通过 Cron 表达式定期执行 IP 优化
 - **安全认证**：双重认证机制（授权码 + 管理员密码），数据加密存储

## 🚀 快速部署

### 方法一：直接上传到 Cloudflare Workers（推荐）

1. **登录 Cloudflare Dashboard**
   - 访问 [Cloudflare Dashboard](https://dash.cloudflare.com/)
   - 选择您的域名或创建新的 Workers

2. **创建 Worker**
   - 点击左侧菜单 "Workers 和 Pages"
   - 点击 "创建应用程序"
   - 选择 "创建 Worker"
   - 输入 Worker 名称（如：ip-optimizer）

3. **上传代码**
   - 将 `web-config-manager-cloudflare.js` 文件内容完整复制
   - 粘贴到 Cloudflare Workers 编辑器中
   - 点击 "保存并部署"

### 方法二：使用 Wrangler CLI

```bash
# 安装 Wrangler CLI
npm install -g wrangler

# 登录 Cloudflare
wrangler login

# 创建新项目
wrangler init ip-optimizer

# 复制代码文件
cp web-config-manager-cloudflare.js ./src/index.js

# 部署
wrangler deploy
```

## ⚙️ 环境变量配置

在 Cloudflare Workers 设置中添加以下环境变量：

### 必需环境变量

| 变量名 | 类型 | 说明 | 示例值 |
|--------|------|------|--------|
| `CLOUDFLARE_API_TOKEN` | 密钥 | Cloudflare API 令牌 | `your_api_token_here` |
| `CLOUDFLARE_ZONE_ID` | 文本 | Cloudflare Zone ID | `32位十六进制字符串` |
| `JWT_SECRET` | 密钥 | JWT 签名密钥 | `your_jwt_secret_here` |
| `ADMIN_PASSWORD` | 密钥 | 管理员密码 | `your_admin_password` |

### 获取 Cloudflare API 信息

1. **获取 API Token**：
   - 访问 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
   - 点击 "创建令牌"
   - 选择 "自定义令牌"
   - 权限设置：
     - Zone:Zone:Read
     - Zone:DNS:Edit
   - 区域资源：包含您要管理的域名

2. **获取 Zone ID**：
   - 在 Cloudflare Dashboard 中选择您的域名
   - 右侧边栏可以看到 Zone ID

## 🗄️ KV 存储配置

1. **创建 KV 命名空间**：
   - 在 Cloudflare Dashboard 中选择 "Workers 和 Pages"
   - 点击 "KV"
   - 创建新的命名空间，名称为 `IP_STORE`

2. **绑定 KV 命名空间**：
   - 在 Worker 设置中找到 "变量"
   - 在 "KV 命名空间绑定" 中添加：
     - 变量名：`IP_STORE`
     - KV 命名空间：选择刚创建的命名空间

## ⏰ 定时任务配置

1. **添加 Cron 触发器**：
   - 在 Worker 设置中找到 "触发器"
   - 点击 "添加 Cron 触发器"
   - 输入 Cron 表达式：`0 */12 * * *`（每12小时执行一次）

## 🔐 安全配置

### 密码安全

- 管理员密码通过环境变量 `ADMIN_PASSWORD` 设置
- 建议使用强密码（包含大小写字母、数字、特殊字符）

## 📱 通知配置

### Telegram Bot 通知

1. 创建 Telegram Bot：
   - 与 @BotFather 对话
   - 发送 `/newbot` 创建新 Bot
   - 获取 Bot Token

2. 获取 Chat ID：
   - 与您的 Bot 对话
   - 访问：`https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
   - 从返回结果中获取 chat_id

## 🎯 使用说明

### 首次登录

1. 访问您的 Worker 域名（如 `https://ip-optimizer.<your-subdomain>.workers.dev`）
2. 根据提示输入部署时设置的授权码以验证身份
3. 再输入 `ADMIN_PASSWORD` 对应的管理员密码即可登录

### 基本配置

1. **IP 筛选条件**：
   - 最小带宽（MB）
   - 最小速度（kB/s）
   - 最大延迟（毫秒）
   - 最大 IP 数量

2. **域名配置**：
   - 添加需要优化的域名
   - 设置记录类型（通常为 A）
   - 设置 TTL 值

3. **通知配置**：
   - 配置息知或 Telegram 通知
   - 测试通知功能

### 功能使用

- **手动获取 IP**：点击"获取优选 IP"按钮
- **查看当前 IP**：查看系统当前使用的优选 IP
- **立即应用**：将选中的 IP 立即应用到 DNS 记录
- **系统状态**：查看最后更新时间和系统状态

## 🔧 故障排除

### 常见问题

1. **IP 获取失败**：
   - 检查网络连接
   - Cloudflare Workers 可能无法访问某些外部数据源
   - 系统会自动使用备用 IP 列表

2. **DNS 更新失败**：
   - 检查 CLOUDFLARE_API_TOKEN 权限
   - 确认 CLOUDFLARE_ZONE_ID 正确
   - 检查域名是否在 Cloudflare 管理

3. **通知发送失败**：
   - 检查息知 Key 是否正确
   - 检查 Telegram Bot Token 和 Chat ID
   - 查看系统日志获取详细错误信息
4. **无法打开 Web 管理界面或登录页面显示“服务器内部错误”**：
    - 刷新页面或清除浏览器缓存后重试
    - 确认网络连接稳定，并排除本地代理或防火墙影响
    - 检查环境变量（`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID`, `JWT_SECRET`, `ADMIN_PASSWORD`）是否完整
    - 检查 `IP_STORE` KV 命名空间是否已创建并绑定到 Worker
    - 确认域名 DNS 记录已正确指向 Cloudflare Workers
    - 如需更多错误信息，可将 `LOG_LEVEL` 设置为 `debug`，然后在 Cloudflare Dashboard 或使用 `wrangler tail` 查看实时日志

## 🔄 更新日志

### v1.0.0
- 初始版本发布
- 支持微测网数据获取
- 支持 Cloudflare DNS 更新
- 支持息知和 Telegram 通知
- 提供 Web 管理界面
- 数据来源于公开网络

## ⭐ 支持项目

如果这个项目对您有帮助，请考虑：

- ⭐ 给项目点个Star
- 🔄 分享给更多人
- 📝 提供反馈和建议
- 🤝 参与项目贡献

---

**⚠️ 重要提醒**：
- 请确保您有权限管理相关域名的DNS记录
- 正确配置所有必需的环境变量
- 建议先在测试环境验证功能

## 📄 许可证

本项目基于 [MIT License](LICENSE) 开源发布。
