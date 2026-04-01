# CliproxyAccountCleaner

---

<p align="center"><strong>⭐ <a href="https://ai.hsnb.fun/aiplanhub">AIPlanHub</a> — 一站式对比国内主流 AI 订阅方案，覆盖编程 · 视频 · 音频多场景，帮你找到性价比最高的选择 ⭐</strong></p>

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
Copy-Item .
