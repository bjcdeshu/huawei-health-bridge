# Huawei Health Bridge

Self-hosted, privacy-first Huawei Training Camp data collection and analysis CLI.

将本人授权的华为 Training Camp 云端数据，整理为本地私有 SQLite 和统一 JSON 查询入口，供个人或 AI 助手读取与分析。核心只有 **Python 标准库、SQLite、一个 CLI 和可选的 systemd 定时器**。

这是非官方个人项目。当前适配中国大陆 Training Camp 接口，不保证其他地区、账号或设备可用，也不保证接口长期不变。它不是医疗诊断工具。

## 能做什么

- 读取运动概要、睡眠摘要、静息心率、睡眠 HRV、全天心率日极值、血氧日统计及最新 VO2max 测量点。
- 保存规范化白名单数据，不持久化 GPS、轨迹、原始健康响应。
- 用官方二维码与本人手机确认配对；私有浏览器会话可在允许时恢复授权。
- 分段回填最近一年、保存查询覆盖、断点续跑。覆盖查询可读取更早的本地记录。
- 按明确日期范围生成分析数据：缺失日期、有效样本数、主睡眠与其他会话、基线比较、测量时间和字段质量。
- 对不完整的新响应保留上一有效字段，并明确标记 retained；不把旧值伪装成新测量。
- 在原定时采集内按有限请求预算补查中断区间，不新增调度服务或消息推送。

## 明确不做什么

不接收他人的账号凭据，不绕过登录或权限。不提供公网健康 API、MCP 服务、看板或自动医学评分。不把运动步数当全天步数，不把日统计当逐秒数据，不把空值补成零。HRV 和 VO2max 未核实的单位保持 `null`；旧 VO2max 不充当近期恢复信号。

## 先运行离线测试

要求 Linux 和 Python 3.12。浏览器配对依赖是可选的，离线测试不需要华为账号或 Playwright。

```sh
git clone https://github.com/bjcdeshu/huawei-health-bridge.git
cd huawei-health-bridge
mkdir -p .test-tmp
TMPDIR="$PWD/.test-tmp" python3 -B tools/run_tests.py
python3 -B health.py capabilities
```

生产授权和定时采集的部署步骤见 [部署说明](docs/deployment.md)。不要把现有账号数据复制进仓库目录。

## 统一命令

以下查询只读本地状态，不会读取认证内容或触发云端请求：

```sh
python3 -B health.py status
python3 -B health.py latest
python3 -B health.py report --limit 14
python3 -B health.py analyze --days 7 --baseline-days 28
python3 -B health.py analyze --days 30 --baseline-days 28
python3 -B health.py history-status --days 365
python3 -B health.py recovery-status
```

`analyze` 默认选最近七个**已结束的北京时间日期**。`--start YYYY-MM-DD --end YYYY-MM-DD` 指定范围；显式包含今天或使用 `--include-today` 时，返回未结束日期标记。分析规则、缺项和解释边界见 [分析说明](docs/analysis.md)。

联网命令要求本人已完成官方授权：

```sh
python3 -B health.py sync --catch-up --catch-up-max-calls 2
python3 -B health.py backfill --days 365
python3 -B health.py catchup --max-calls 12
```

首次历史回填应显式执行 `backfill`，不能把没有旧运行记录的冷启动判为一年停机。`catchup` 只修复已识别的采集中断；数据没测到与采集没执行是不同状态。

状态目录默认 `/var/lib/huawei-training-camp`，目录权限 `0700`、文件 `0600`。可使用 `--state-dir DIR` 查询其他同结构私有状态目录。认证自动协调与浏览器部署使用上述标准私有目录。

## 隐私与安全

仓库只包含源码、合成测试和通用文档。不要提交真实数据库、Cookie、令牌、二维码、原始响应、个人分析报告或运行日志；`.gitignore` 不是完整的防泄漏保证。见 [安全说明](SECURITY.md)。

`status`、定时采集日志只包含状态、时间和数量。`latest`、`report`、`analyze` 会向调用者返回个人测量数据；输出不得重定向进 Git 工作树或公开日志。将结果交给 AI 助手时，还应评估所用模型服务的数据处理方式。

## 项目结构

- `health.py`：统一 CLI 与日常采集协调。
- `health_sources.py`、`sleep_collector.py`、`health_points.py`：受限来源适配。
- `health_storage.py`：缺项保护和字段级来源时间。
- `health_history.py`、`health_recovery.py`：历史覆盖与中断补采。
- `health_analysis.py`：确定性、只读的日期范围计算。
- `auth_session.py`、`browser_session.py`：官方授权与低权限浏览器。
- `app.py`、`collector.py`、`sync.py`：复用底座和保留的旧兼容入口；日常使用 `health.py`。
- `test_*.py`：合成回归，不包含真实账号响应。

## 许可与来源

MIT。项目参考上游 [huawei-training-camp-mcp-connector](https://github.com/yinxu-xiong/huawei-training-camp-mcp-connector)，保留上游署名，详见 [第三方声明](THIRD_PARTY_NOTICES.md)。
