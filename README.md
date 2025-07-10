# Cloudflare Workers 完全小白部署教程

本文将带你一步一步在 **零基础** 情况下把本仓库的 IP 优化系统部署到 Cloudflare Workers。

## 准备工作

1. **注册 Cloudflare 账号**：访问 [https://dash.cloudflare.com/](https://dash.cloudflare.com/) 按提示完成注册。
2. **域名托管到 Cloudflare**：如果还没有域名，先购买一个并在 Cloudflare 添加站点，按照向导把域名的 DNS 服务器切换到 Cloudflare 提供的地址。
3. **下载本仓库文件**：点击 GitHub 上的 "Code" 按钮选择 `Download ZIP`，下载后解压得到 `web-config-manager-cloudflare.js` 文件。

## 开始部署

### 第一步：创建 Worker

1. 登录 Cloudflare 后进入主页，在左侧找到 **"Workers 和 Pages"** 并点击。
2. 第一次使用会要求设置子域名，按提示填入一个名称即可。
3. 点击 **"创建应用程序"** ，在弹出的选项里选择 **"创建 Worker"**。
4. 输入一个名称，例如 `ip-optimizer`，然后点击 **"部署"**。

### 第二步：上传代码

1. 部署完成后会自动跳转到代码编辑界面，删除里面的示例代码。
2. 打开刚刚下载的 `web-config-manager-cloudflare.js`，全选复制。
3. 回到浏览器，把代码粘贴到编辑器中。
4. 点击右上角的 **"保存并部署"** 按钮。

### 第三步：准备 API Token 和 Zone ID

1. 另开浏览器标签页访问 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens) 并登录。
2. 点击 **"创建令牌"** → 选择 **"自定义令牌"**。
3. 权限设置两行：
   - `Zone` → `Zone` → `Read`
   - `Zone` → `DNS` → `Edit`
4. 区域资源选择「包含 → 特定区域」，并选择要管理的域名。
5. 点击 **"继续以显示摘要"** 后确认信息，再点击 **"创建令牌"**。
6. 复制显示的 Token，稍后需要用到。（只会出现一次）
7. 回到 Cloudflare 控制面板主页，进入你的域名，在右侧可以看到 **Zone ID**，同样复制保存。

### 第四步：创建并绑定 KV 命名空间

1. 在左侧菜单点击 **"Workers 和 Pages"**，然后选择 **"KV"**。
2. 点击 **"创建命名空间"**，名称输入 `IP_STORE`，确认添加。
3. 回到你刚才创建的 Worker 页面，切到 **"设置"** 标签。
4. 在 **"KV 命名空间绑定"** 部分点击 **"编辑变量"**，再点击 **"添加绑定"**：
   - 变量名填 `IP_STORE`
   - 选择刚建立的 `IP_STORE` 命名空间
5. 保存并再次部署。

### 第五步：配置环境变量

1. 仍在 Worker 的 **"设置"** 页面，在 **"环境变量"** 部分点击 **"编辑变量"**。
2. 依次添加以下四个变量：
   - `CLOUDFLARE_API_TOKEN`：填入第 3 步获得的 Token
   - `CLOUDFLARE_ZONE_ID`：填入第 3 步获得的 Zone ID
   - `JWT_SECRET`：可以随便填一个不容易猜到的随机字符串
   - `ADMIN_PASSWORD`：以后登录管理界面时使用的密码
3. 保存并部署。

### 第六步：设置定时任务（可选）

1. 在同一个页面找到 **"触发器"**，点击 **"添加 Cron 触发器"**。
2. 输入 `0 */12 * * *`，表示每 12 小时自动执行一次 IP 优化任务。
3. 点击保存后再次部署。

### 第七步：访问和初次登录

1. 在 Worker 概览页可以看到一个类似 `https://ip-optimizer.your-subdomain.workers.dev` 的地址，点击打开。
2. 首次登录需要输入默认授权码 `beiji` 和刚刚设置的 `ADMIN_PASSWORD`。
3. 成功登录后即可看到友好的 Web 管理界面。

## 常见问题

- **看不到登录界面或提示错误？** 请检查环境变量是否设置完整，以及 `IP_STORE` 命名空间是否正确绑定。
- **DNS 更新失败？** 重新检查 API Token 权限和 Zone ID 是否匹配你的域名。
- **获取 IP 超时？** 可能是 Cloudflare Workers 无法访问数据源，系统会自动使用备用 IP 列表。

## 完成

到这里，IP 优化系统就部署好了。之后系统会按照你的设置自动获取 IP 并更新 DNS，也可以在页面上手动操作和查看状态。

如需更深入的说明，可参阅仓库中的 [DEPLOYMENT.md](DEPLOYMENT.md) 文档。

## 解析微测网 IP

现在无需单独运行脚本，Worker 已内置从 [WeTest](https://www.wetest.vip/page/edgeone/address_v4.html) 解析 IP 的功能。
直接访问 API 即可获取列表：

```bash
curl https://<your-worker>/api/wetest-ip-list
```

API 返回包含线路、IP、带宽等字段的 JSON，方便后续筛选或自动解析 DNS。

