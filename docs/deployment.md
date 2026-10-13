# Linux 私有部署

本说明来自 Ubuntu 24.04、Python 3.12 和 systemd 的既有部署。其他发行版、地区账号、设备组合及全新机器安装的全部变体尚未验证。核心采集不依赖第三方 Python 包；浏览器授权需要 Playwright 和 Chromium。

## 1. 准备代码和私有目录

以下命令以有 sudo 权限的管理员执行。安装路径采用 `/opt/huawei-health-bridge`；若选择其他路径，必须同步修改 systemd 单元中的两个路径。

```sh
sudo git clone https://github.com/bjcdeshu/huawei-health-bridge.git /opt/huawei-health-bridge
sudo useradd --system --home-dir /var/lib/huawei-training-camp-browser --shell /usr/sbin/nologin health-browser
sudo install -d -m 0700 /var/lib/huawei-training-camp
sudo install -d -m 0700 -o health-browser -g health-browser /var/lib/huawei-training-camp-browser
sudo install -d -m 0700 -o health-browser -g health-browser /var/lib/huawei-training-camp-browser/runtime-tmp
```

若用户或目录已存在，先核对所有者和用途，不要覆盖其他部署。不应将私有状态目录放在仓库或共享同步目录内。

## 2. 安装隔离浏览器

```sh
sudo apt-get update
sudo apt-get install -y python3 python3-venv
cd /opt/huawei-health-bridge
sudo python3 -m venv .browser-venv
sudo .browser-venv/bin/pip install -r requirements-browser.txt
sudo .browser-venv/bin/python -m playwright install-deps chromium
sudo env PLAYWRIGHT_BROWSERS_PATH=/opt/huawei-health-bridge/.browser-runtime .browser-venv/bin/python -m playwright install --only-shell chromium
```

代码和浏览器二进制应允许 `health-browser` 读取和执行，但该用户不应拥有代码写权限。浏览器运行时始终使用私有临时目录。

Ubuntu 的 user namespace 限制可能阻止 Chromium 沙箱。此时先定位真实 Chromium headless shell 可执行文件，再将完整路径填入 `deploy/chromium.apparmor.in`，另存为 `/etc/apparmor.d/huawei-training-camp-chromium` 并由管理员加载。模板中的占位符不能直接使用。该 profile 只授权项目二进制的 userns，不修改全局限制，不使用 `--no-sandbox`。

## 3. 本人完成官方配对

```sh
cd /opt/huawei-health-bridge
sudo python3 -B auth_session.py pair --wait 240
```

程序启动低权限官方浏览器，并在需要时输出私有二维码文件路径。管理员通过可信本地查看或 SFTP 获取当前二维码，本人在手机完成官方确认。二维码短期有效，不能上传公开图床；密码、验证码、Cookie 和令牌不要粘贴到聊天或 Issue。

配对成功必须返回 `status=ok` 和 `vps_auth_verified=true`。这表示浏览器导出的授权已经通过实际数据接口校验；仅完成网页跳转不算成功。后续被提供方撤销授权时仍可能需要重新配对。

可选的 Telegram 二维码投递需要显式 `--chat-id`、`--topic-id` 和本地环境变量 `HUAWEI_TELEGRAM_BOT_TOKEN`。默认本地配对不依赖 Telegram 或 Hermes。不要将令牌写入命令参数、仓库或公开日志。

## 4. 执行与验证

```sh
sudo python3 -B health.py sync
sudo python3 -B health.py status
sudo python3 -B health.py analyze --days 7 --baseline-days 28
```

`status` 不包含测量值。`analyze` 包含个人数据，只应在私有终端运行。睡眠 `partial` 可以表示缺少评分或分期，不一定表示请求失败；认证、采集成功与测量新鲜度应分别检查。

需要历史时再执行：

```sh
sudo python3 -B health.py backfill --days 365
sudo python3 -B health.py history-status --days 365
```

最近一年之外的新云端查询受限；已经保存的旧日期仍可只读查询。空窗口只代表查询为空，不代表没有活动或身体指标为零。

## 5. 启用原生定时器

```sh
sudo install -m 0644 deploy/huawei-training-camp.service /etc/systemd/system/
sudo install -m 0644 deploy/huawei-training-camp.timer /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/huawei-training-camp.service /etc/systemd/system/huawei-training-camp.timer
sudo systemctl daemon-reload
sudo systemctl start huawei-training-camp.service
sudo systemctl show huawei-training-camp.service -p Result -p ExecMainStatus
sudo systemctl enable --now huawei-training-camp.timer
sudo systemctl show huawei-training-camp.timer -p ActiveState -p NextElapseUSecRealtime
```

示例每天北京时间 12:00、22:00 采集。每轮额外补采最多两个历史请求；剩余缺口保留到下轮。服务完成后 inactive 是 oneshot 的正常状态。服务超时与任何来源失败都不应清空历史。

停止未来采集可执行 `sudo systemctl disable --now huawei-training-camp.timer`。停止定时器不会删除数据库或官方会话。

## 故障处理

- `auth_check_error`：认证检查暂时失败，先查浏览器或网络，不等同于需要扫码。
- `reauth_required` 且 `authentication.requires_user=true`：按官方配对流程处理。
- `storage_error`：核对私有目录所有者、权限和 SQLite 状态，不要删除数据库重试。
- `coverage_limited`：查询限额仍未解除；不要把该区间当完整数据。
- `recovery-status` 的未完成区间：已有查询预算和恢复进度，可用 `catchup --max-calls 12` 有界继续，不要并发重复启动。

公开问题报告只附状态码和合成复现，不附实际个人记录或认证材料。
