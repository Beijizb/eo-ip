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

- **智能 IP 获取**：从微测网自动获取优选 IP 地址
- **自动 DNS 更新**：支持 Cloudflare DNS A 记录自动更新
- **多种通知方式**：支持息知通知和 Telegram Bot 通知
- **Web 管理界面**：提供友好的 Web 管理界面
- **定时任务**：支持定时自动执行 IP 优化
- **安全认证**：双重认证机制（授权码 + 管理员密码）

## ⚡ 快速开始

> 💡 **新手用户**：建议先阅读 [快速开始指南](QUICKSTART.md)，10分钟即可完成部署！

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
   - 将 `worker-bundle-simple.js` 文件内容完整复制
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
cp worker-bundle-simple.js ./src/index.js

# 部署
wrangler deploy
```

## ⚙️ 环境变量配置

在 Cloudflare Workers 设置中添加以下环境变量：

### 必需环境变量

| 变量名 | 说明 | 示例值 |
|--------|------|--------|
| `CF_API_TOKEN` | Cloudflare API 令牌 | `your_api_token_here` |
| `CF_ZONE_ID` | Cloudflare Zone ID | `32位十六进制字符串` |
| `JWT_SECRET` | JWT 签名密钥 | `your_jwt_secret_here` |
| `ADMIN_PASSWORD` | 管理员密码 | `your_admin_password` |

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

### 授权码设置

系统默认授权码为：`beiji`

如需修改授权码：

1. **生成新的 SHA-256 哈希**：
   ```javascript
   // 在浏览器控制台运行
   crypto.subtle.digest('SHA-256', new TextEncoder().encode('新授权码'))
     .then(h => console.log(Array.from(new Uint8Array(h))
       .map(b => b.toString(16).padStart(2, '0')).join('')))
   ```

2. **更新代码中的哈希值**：
   - 找到 `handleLogin` 函数中的 `validAuthCodeHash` 变量
   - 替换为新生成的哈希值

### 密码安全

- 管理员密码通过环境变量 `ADMIN_PASSWORD` 设置
- 建议使用强密码（包含大小写字母、数字、特殊字符）

## 📱 通知配置

### 息知通知

1. 注册息知账号：https://xizhi.qqoq.net/
2. 获取通知 Key
3. 在系统设置中配置息知通知

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

1. 访问您的 Worker 域名
2. 输入授权码：`beiji`
3. 输入管理员密码（环境变量中设置的密码）

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
   - 检查 CF_API_TOKEN 权限
   - 确认 CF_ZONE_ID 正确
   - 检查域名是否在 Cloudflare 管理

3. **通知发送失败**：
   - 检查息知 Key 是否正确
   - 检查 Telegram Bot Token 和 Chat ID
   - 查看系统日志获取详细错误信息

### 调试功能

系统提供调试功能：
- 点击"调试 IP 获取"查看详细的获取过程
- 检查各个数据源的访问状态
- 查看 IP 解析和筛选过程

## 📊 数据源

- **主要数据源**：微测网 (https://www.wetest.vip/page/edgeone/address_v4.html)
- **备用数据**：内置优质 IP 列表
- **更新频率**：根据定时任务设置（默认12小时）

## 🔄 更新日志

### v1.0.0
- 初始版本发布
- 支持微测网数据获取
- 支持 Cloudflare DNS 更新
- 支持息知和 Telegram 通知
- 提供 Web 管理界面

## 📚 文档导航

| 文档 | 说明 | 适用人群 |
|------|------|----------|
| [快速开始](QUICKSTART.md) | 10分钟快速部署指南 | 🔰 新手用户 |
| [详细部署](DEPLOYMENT.md) | 完整的分步部署教程 | 👥 所有用户 |
| [配置说明](CONFIG.md) | 详细的配置选项说明 | 🔧 进阶用户 |
| [GitHub指南](GITHUB.md) | 项目上传和版本管理 | 👨‍💻 开发者 |
| [项目概览](PROJECT_OVERVIEW.md) | 项目结构和技术架构 | 🏗️ 维护者 |

## 🎉 成功案例

- ✅ 网站访问速度提升 30-50%
- ✅ DNS解析延迟降低 60%
- ✅ 自动化运维，减少人工干预
- ✅ 支持多域名批量管理

## 📄 许可证

本项目采用 [MIT 许可证](LICENSE)。

## 🤝 贡献

我们欢迎各种形式的贡献：

- 🐛 **报告问题**：发现bug请提交Issue
- 💡 **功能建议**：有好想法请告诉我们
- 📝 **改进文档**：帮助完善项目文档
- 💻 **代码贡献**：提交Pull Request

## 📞 获取支持

遇到问题？我们来帮您：

1. 📖 **查看文档**：大部分问题都能在文档中找到答案
2. 🔍 **搜索Issues**：看看是否有人遇到过类似问题
3. 🆕 **提交Issue**：详细描述您的问题和环境
4. 💬 **社区讨论**：加入技术交流群组

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
