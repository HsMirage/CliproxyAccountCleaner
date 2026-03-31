# CliproxyAccountCleaner

---

<p align="center"><strong>⭐ <a href="https://github.com/HsMirage/AIPlanHub">AIPlanHub</a> — 一站式对比国内主流 AI 订阅方案，覆盖编程 · 视频 · 音频多场景，帮你找到性价比最高的选择 ⭐</strong></p>

---

面向 CLIProxy 管理端的账号巡检与批量处理工具。

当前提供 3 种运行方式：

- 桌面模式（Tk）
- 网页模式（默认入口）
- CLI 交互模式（适合服务器 / 容器 / 远程终端）

同时支持 Docker 部署，并带有网页登录保护。

## 当前能力

### 检测

- 401 无效检测
- 额度检测（周额度 + 5 小时额度）
- 联合检测（401 + 额度）

### 批量动作

- 关闭选中账号
- 恢复已关闭账号
- 永久删除账号
- 加入备用池
- 备用转活跃（检测后再开启）

### 自动巡检

- 按间隔自动执行联合检测
- 401 账号可自动删除或仅标记
- 额度耗尽账号可自动关闭、删除或仅标记
- 支持活跃账号目标数
- 活跃数不足时优先从备用池补齐，可选继续扫描已关闭账号

### 运行与部署

- Web 模式登录页与会话管理
- Docker / Docker Compose 部署
- 无 `tkinter` 环境下可直接使用 Web 模式

## 项目结构

```text
CliproxyAccountCleaner.py      主入口，默认启动 Web 模式
CliproxyAccountCleaner_cli.py  CLI 交互模式
cliproxy_web_mode.py           Web 端逻辑
config.example.json            配置模板
Dockerfile
docker-compose.yml
pyproject.toml
```

## 快速开始

### 1. 准备配置

仓库默认提交的是模板文件，请先复制一份真实配置：

```powershell
Copy-Item .\config.example.json .\config.json
```

或：

```bash
cp ./config.example.json ./config.json
```

`config.json` 已被 `.gitignore` 忽略，不会进入版本控制。

### 2. 本地运行

推荐使用 `uv`：

```bash
uv run .\CliproxyAccountCleaner.py --no-browser
```

默认是 Web 模式，访问：

```text
http://127.0.0.1:8765
```

桌面模式：

```bash
uv run .\CliproxyAccountCleaner.py --desktop
```

CLI 模式：

```bash
uv run .\CliproxyAccountCleaner_cli.py
```

如果不用 `uv`，也可以直接安装依赖后运行：

```bash
pip install requests aiohttp
python CliproxyAccountCleaner.py --no-browser
```

## 运行模式说明

### Web 模式

- `CliproxyAccountCleaner.py` 默认进入 Web 模式
- 支持刷新、401 检测、额度检测、联合检测
- 支持关闭、恢复、删除、备用池管理
- 支持自动巡检和关闭进度展示
- 可通过 `web_login_username` / `web_login_password` 开启登录保护

启动参数：

```bash
python CliproxyAccountCleaner.py --host 127.0.0.1 --port 8765 --no-browser
```

### 桌面模式

```bash
python CliproxyAccountCleaner.py --desktop
```

说明：

- 需要 `tkinter`
- 更适合本地 Windows 环境
- 在 Docker / 无桌面环境中请改用 Web 或 CLI 模式

### CLI 模式

```bash
python CliproxyAccountCleaner_cli.py
```

CLI 版适合服务器或 SSH 环境，支持：

- 手动检测 401 / 额度 / 联合检测
- 批量删除问题账号、关闭额度耗尽账号
- 自动巡检独立状态界面
- 手动长流程按 `Q` 取消
- 自动巡检状态界面支持 `R` 立即执行、`S` 停止、`M` 返回主菜单

## 配置说明

如果你是手工编辑 `config.json`，建议使用下面这一组字段名：

- `base_url`
- `token` 或 `cpa_password`
- `target_type`
- `provider`
- `workers`
- `quota_workers`
- `delete_workers`
- `close_workers`
- `enable_workers`
- `timeout`
- `retries`
- `weekly_quota_threshold`
- `primary_quota_threshold`
- `auto_interval_minutes`
- `auto_action_401`
- `auto_action_quota`
- `auto_keep_active_count`
- `auto_allow_scan_closed`
- `standby_output`
- `web_login_username`
- `web_login_password`

示例：

```json
{
  "base_url": "http://127.0.0.1:2083",
  "token": "your-token",
  "target_type": "codex",
  "provider": "",
  "workers": 100,
  "quota_workers": 100,
  "delete_workers": 20,
  "close_workers": 20,
  "enable_workers": 20,
  "timeout": 10,
  "retries": 1,
  "weekly_quota_threshold": 99,
  "primary_quota_threshold": 99,
  "auto_interval_minutes": 30,
  "auto_action_401": "删除",
  "auto_action_quota": "关闭",
  "auto_keep_active_count": 0,
  "auto_allow_scan_closed": false,
  "standby_output": "standby_accounts.json",
  "web_login_username": "",
  "web_login_password": ""
}
```

说明：

- `token` 与 `cpa_password` 兼容，建议只维护 `token`
- `web_login_username` 和 `web_login_password` 都留空时，Web 模式按免登录运行
- 只填其中一个登录字段时，系统会降级为免登录并给出提示
- Web 界面会兼容旧配置，不要求你手动迁移已有文件

## 自动巡检配置

GUI、CLI、Web 共用以下行为：

- `auto_interval_minutes`：自动巡检间隔（分钟）
- `auto_action_401`：401 账号自动处理方式，支持 `删除` / `仅标记`
- `auto_action_quota`：额度耗尽账号自动处理方式，支持 `关闭` / `删除` / `仅标记`
- `auto_keep_active_count`：活跃账号目标数，`<= 0` 视为不限制
- `auto_allow_scan_closed`：备用池不足时，是否允许从已关闭账号补位

巡检核心流程：

1. 刷新账号并执行联合检测
2. 按策略处理 401 / 额度异常账号
3. 活跃账号超出目标时回收
4. 活跃账号不足时优先从备用池补齐，再按配置决定是否扫描已关闭账号

## Docker 部署

### Docker Compose

先准备本地配置文件：

```powershell
Copy-Item .\config.example.json .\config.json
```

然后启动：

```bash
docker compose up -d --build
```

访问：

```text
http://127.0.0.1:8765
```

停止：

```bash
docker compose down
```

### 纯 Docker

构建镜像：

```bash
docker build -t cliproxy-account-cleaner:latest .
```

运行容器：

```bash
docker run -d ^
  --name cliproxy-account-cleaner ^
  -p 8765:8765 ^
  -v %cd%/config.json:/app/config.json ^
  cliproxy-account-cleaner:latest
```

Linux/macOS 请把 `%cd%` 改为 `$(pwd)`。

说明：

- 镜像构建阶段会把 `config.example.json` 放到容器内作为默认 `config.json`
- 生产环境建议通过挂载真实 `config.json` 覆盖

## 常见操作流程

### Web / GUI

1. 刷新账号列表
2. 执行 401、额度或联合检测
3. 根据结果关闭、恢复、删除或调整备用池

### CLI

1. 启动 `CliproxyAccountCleaner_cli.py`
2. 在主菜单选择检测动作
3. 需要自动巡检时进入自动巡检状态界面

## 常见问题

### 启动报 `config.json 格式错误`

- 检查 JSON 语法
- 建议使用 UTF-8 保存
- 当前版本已兼容 UTF-8 BOM

### Docker 容器里不能用桌面模式

这是预期行为。容器环境通常没有 `tkinter` 和桌面系统，请使用默认 Web 模式。

### 登录后又回到登录页

- 检查浏览器是否拦截 Cookie
- 检查系统时间是否异常
- 确认 `web_login_username` / `web_login_password` 配置完整

## 使用建议

- 删除前务必二次确认，删除不可恢复
- 不要把真实 `config.json` 提交到仓库
- 生产环境请修改网页登录默认口令或留空关闭登录
- 建议配合反向代理启用 HTTPS

### 请求打赏 10LDC

https://credit.linux.do/paying/online?token=0a1672d8210f616307549945132ac09489624ff61e81f67c0e23376df72bc37e

## 合规与免责声明

本工具仅用于运维与测试场景。请确保你的使用行为符合平台条款及当地法律法规。

本软件为免费软件，请勿出售；如果你在其他地方购买，请申请退款。
