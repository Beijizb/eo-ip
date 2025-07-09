# IP优化系统详细部署教程

本教程将详细指导您如何从零开始部署 IP 优化系统到 Cloudflare Workers。

## 📋 部署前准备

### 1. 账号准备

- **Cloudflare 账号**：免费账号即可
- **域名**：需要在 Cloudflare 托管的域名

### 2. 文件准备

确保您有以下文件：
- `web-config-manager-cloudflare.js` - 主程序文件

## 🚀 详细部署步骤

### 第一步：登录 Cloudflare

1. 打开浏览器，访问 [https://dash.cloudflare.com/](https://dash.cloudflare.com/)
2. 使用您的 Cloudflare 账号登录
3. 如果没有账号，点击"注册"创建新账号

### 第二步：创建 Worker

1. **进入 Workers 管理页面**
   - 在左侧菜单中找到并点击 "Workers 和 Pages"
   - 如果是第一次使用，可能需要设置子域名

2. **创建新的 Worker**
   - 点击右上角的 "创建应用程序" 按钮
   - 选择 "创建 Worker"
   - 输入 Worker 名称，例如：`ip-optimizer`
   - 点击 "部署" 按钮

3. **编辑 Worker 代码**
   - 部署完成后，点击 "编辑代码" 按钮
   - 删除默认代码
   - 打开 `web-config-manager-cloudflare.js` 文件
   - 复制所有内容并粘贴到编辑器中
   - 点击右上角 "保存并部署" 按钮

### 第三步：获取 Cloudflare API 信息

#### 获取 API Token

1. **创建 API Token**
   - 访问 [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
   - 点击 "创建令牌" 按钮
   - 选择 "自定义令牌"

2. **配置令牌权限**
   - **令牌名称**：输入 `IP-Optimizer-Token`
   - **权限设置**：
     - 第一行：Zone | Zone | Read
     - 第二行：Zone | DNS | Edit
   - **区域资源**：
     - 选择 "包含" | "特定区域"
     - 选择您要管理的域名
   - **客户端 IP 地址筛选**：留空（可选）
   - **TTL**：留空（可选）

3. **创建并保存 Token**
   - 点击 "继续以显示摘要"
   - 确认设置无误后点击 "创建令牌"
   - **重要**：复制生成的 Token 并妥善保存（只显示一次）

#### 获取 Zone ID

1. **找到 Zone ID**
   - 回到 Cloudflare Dashboard 主页
   - 点击您要管理的域名
   - 在右侧边栏找到 "Zone ID"
   - 复制这个 32 位的十六进制字符串

### 第四步：创建 KV 存储

1. **创建 KV 命名空间**
   - 在 Cloudflare Dashboard 中点击 "Workers 和 Pages"
   - 点击左侧的 "KV"
   - 点击 "创建命名空间"
   - 命名空间名称输入：`IP_STORE`
   - 点击 "添加"

2. **绑定 KV 到 Worker**
   - 回到您的 Worker 管理页面
   - 点击 "设置" 选项卡
   - 找到 "变量" 部分
   - 在 "KV 命名空间绑定" 中点击 "编辑变量"
   - 点击 "添加绑定"
   - **变量名**：`IP_STORE`
   - **KV 命名空间**：选择刚创建的 `IP_STORE`
   - 点击 "保存并部署"

### 第五步：配置环境变量

1. **添加环境变量**
   - 在 Worker 设置页面的 "变量" 部分
   - 在 "环境变量" 中点击 "编辑变量"
   - 逐一添加以下变量：

2. **必需的环境变量**

    | 变量名 | 类型 | 值 | 说明 |
    |--------|------|----|----|
    | `CLOUDFLARE_API_TOKEN` | 密钥 | 您的 API Token | 第三步获取的 Token |
    | `CLOUDFLARE_ZONE_ID` | 文本 | 您的 Zone ID | 第三步获取的 Zone ID |
    | `JWT_SECRET` | 密钥 | 随机字符串 | 用于 JWT 签名，建议32位随机字符 |
    | `ADMIN_PASSWORD` | 密钥 | 您的管理员密码 | 登录系统用的密码 |

3. **生成 JWT_SECRET**
   - 可以使用在线工具生成：[https://www.random.org/strings/](https://www.random.org/strings/)
   - 或在浏览器控制台运行：
     ```javascript
     Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
     ```

4. **保存变量**
   - 添加完所有变量后点击 "保存并部署"

### 第六步：设置定时任务

1. **添加 Cron 触发器**
   - 在 Worker 设置页面找到 "触发器" 部分
   - 点击 "添加 Cron 触发器"
   - 输入 Cron 表达式：`0 */12 * * *`
   - 这表示每12小时执行一次
   - 点击 "添加触发器"

2. **Cron 表达式说明**
   - `0 */12 * * *` - 每12小时执行一次
   - `0 */6 * * *` - 每6小时执行一次
   - `0 0 */1 * *` - 每天执行一次
   - `0 0 * * 0` - 每周执行一次

### 第七步：验证部署

1. **访问系统**
   - 在 Worker 概览页面找到您的 Worker URL
   - 点击访问，应该看到登录页面

2. **首次登录**
   - **授权码**：输入 `beiji`（默认授权码）
   - **管理员密码**：输入您在环境变量中设置的 `ADMIN_PASSWORD`
   - 点击登录

3. **验证功能**
   - 登录成功后应该看到管理界面
   - 尝试点击 "验证 Cloudflare 配置" 按钮
   - 如果显示验证成功，说明 API 配置正确

## 🔧 配置系统

### 基本设置

1. **IP 筛选条件**
   - **最小带宽**：建议设置为 20 MB
   - **最小速度**：建议设置为 2000 kB/s
   - **最大延迟**：建议设置为 200 毫秒
   - **最大 IP 数量**：建议设置为 10

2. **域名配置**
   - 点击 "添加域名"
   - 输入要优化的域名（如：example.com）
   - 记录类型选择 "A"
   - TTL 设置为 300（5分钟）
   - 最大 IP 数设置为 3

### 通知配置

#### 息知通知

1. **注册息知账号**
   - 访问 [https://xizhi.qqoq.net/](https://xizhi.qqoq.net/)
   - 注册并登录账号
   - 创建新的通知渠道
   - 复制通知 Key

2. **配置息知通知**
   - 在系统设置中找到 "通知设置"
   - 启用息知通知
   - 输入您的息知 Key
   - 点击 "测试通知" 验证配置

#### Telegram 通知

1. **创建 Telegram Bot**
   - 在 Telegram 中搜索 @BotFather
   - 发送 `/newbot` 命令
   - 按提示设置 Bot 名称和用户名
   - 保存返回的 Bot Token

2. **获取 Chat ID**
   - 与您的 Bot 发送一条消息
   - 访问：`https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
   - 从返回的 JSON 中找到 `chat.id` 字段

3. **配置 Telegram 通知**
   - 启用 Telegram 通知
   - 输入 Bot Token 和 Chat ID
   - 点击 "测试通知" 验证配置

## ✅ 测试系统

1. **测试 IP 获取**
   - 点击 "获取优选 IP" 按钮
   - 查看是否能成功获取到 IP 列表

2. **测试 DNS 更新**
   - 选择几个获取到的 IP
   - 点击 "立即应用" 按钮
   - 检查是否成功更新 DNS 记录

3. **测试通知功能**
   - 在通知设置中点击 "测试通知"
   - 检查是否收到测试通知

## 🔍 故障排除

### 常见错误及解决方案

1. **"CLOUDFLARE_API_TOKEN环境变量未设置"**
   - 检查环境变量是否正确添加
   - 确认变量名拼写正确

2. **"CLOUDFLARE_ZONE_ID格式不正确"**
   - 确认 Zone ID 是32位十六进制字符串
   - 检查是否有多余的空格

3. **"获取DNS记录失败"**
   - 检查 API Token 权限是否正确
   - 确认域名在 Cloudflare 托管

4. **"IP获取失败"**
   - 这是正常现象，系统会使用备用 IP
   - Cloudflare Workers 可能无法访问某些外部网站

## 🎉 部署完成

恭喜！您已经成功部署了 IP 优化系统。系统将：

- 每12小时自动获取优选 IP
- 自动更新您配置的域名 DNS 记录
- 通过您配置的方式发送通知

如有问题，请参考故障排除部分或查看系统日志。
