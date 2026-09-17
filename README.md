# WeChat Chat Access Skill for macOS（Mac 侧）

> **平台范围：仅适用于 Mac/macOS 侧，不支持 Windows 微信数据库。**

一个供 Codex 使用的 Mac 侧 Skill：只读接入本人 Mac 上的微信 4.x 本地加密数据库，列出会话、读取消息、搜索正文，并在接入失效时提供受控恢复流程。

## 能做什么

- 检查数据库、密钥和消息分片的可读状态
- 按会话、时间范围或关键词查询聊天记录
- 跨普通消息与业务消息分片读取
- 保留 WAL 中的新消息，并对压缩字段做解码
- 在密钥失效时，通过临时微信副本恢复本机读取能力

当前实测范围是 Apple Silicon、macOS 27、微信 4.1.13（build 269602）。其他系统和微信版本需要重新验证，不能据此承诺兼容。

## 安装

把仓库放到 Codex 的 Skills 目录：

```bash
git clone git@github.com:Woltziara/wechat-chat-access.git "$HOME/.codex/skills/wechat-chat-access"
python3 "$HOME/.codex/skills/wechat-chat-access/scripts/setup_runtime.py"
```

然后可直接对 Codex 说：

```text
使用 $wechat-chat-access 检查本机微信聊天记录接入。
```

Skill 的完整使用方式、查询命令和验证边界见 [SKILL.md](SKILL.md)。

## 私有数据边界

仓库不包含聊天记录、数据库、账号配置、密钥、截图或本机绝对路径。运行时的个人配置与密钥保存在：

```text
~/Library/Application Support/CodexWeChatRead/
```

程序以只读方式访问微信数据库。密钥恢复流程会短时退出微信，并使用临时副本；它不会关闭 SIP、重启 Mac、重签原版微信或自动上传聊天数据。运行恢复流程前，请阅读 [macOS 取钥恢复](references/unlock-macos.md)。

## 验证

```bash
python3 "$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py" .
"$HOME/Library/Application Support/CodexWeChatRead/runtime/bin/python" -m unittest discover -s scripts -p 'test_*.py'
```
