# CliproxyAccountCleaner

一个用于 CLIProxy 管理端的批量账号检测与处理工具（当前主要面向 Codex 账号）。

## 重要声明

**本软件为免费软件，请勿出售，如果在其他地方购买，请申请退款。**

## 功能概览

- 拉取管理端 `auth-files` 账号列表
- 批量检查 401 失效状态
- 批量检查额度状态（周额度 + 5 小时额度）
- 批量关闭、恢复、删除账号
- 支持定时检测与自动动作

## 运行环境

- Windows 10 / 11（推荐直接使用 `.exe`）
- 或者任意可运行 Python 的环境（源码运行）
- 可访问 CLIProxy 管理地址

## 配置说明（config.json）

请先编辑同目录下 `config.json`：

- `base_url`：管理端地址（例如 `http://127.0.0.1:2083`）
- `token` 或 `cpa_password`：管理令牌（当前代码会兼容这两个字段）

> 建议只维护 `token` 字段，`cpa_password` 主要用于兼容历史配置。

## 使用方式

### 方式 A：可执行文件（推荐）

1. 下载并解压 Release 中的 `CliproxyAccountCleaner.zip`
2. 修改 `config.json`
3. 双击运行 `CliproxyAccountCleaner.exe`

### 方式 B：源码运行

```bash
python enhanced_ui.py
```

## 常见操作流程

1. 点击“刷新”加载账号
2. 点击“检查401”或“检查额度”
3. 按结果执行“关闭选中 / 恢复已关闭 / 永久删除”

## 打包文件说明

发布压缩包通常包含：

- `CliproxyAccountCleaner.exe`
- `config.json`
- `请读我.txt`

## 使用建议

- 删除前务必二次确认（删除不可恢复）
- 先检测，再批量处理
- 不要公开分享包含真实令牌的 `config.json`

## 合规与免责声明

本工具仅用于运维与测试场景。请确保你的使用行为符合目标平台条款及当地法律法规。
