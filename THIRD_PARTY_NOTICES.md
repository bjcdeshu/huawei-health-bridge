# 第三方来源与许可

本项目参考并改编了 [yinxu-xiong/huawei-training-camp-mcp-connector](https://github.com/yinxu-xiong/huawei-training-camp-mcp-connector) 的华为 Training Camp 数据读取方法。参考版本：`c4b6b5c24ea078e8e17598de732f1ce12bb4a96c`。

该上游采用 MIT License，版权声明为 `Copyright (c) 2026 huawei-health-mcp contributors`。本仓库 `LICENSE` 保留该声明与完整许可；部分源码亦保留原声明。独立增加的统一 CLI、私有 SQLite、认证协调、历史覆盖、分析和回归测试采用同一 MIT 许可。

华为、HUAWEI 和相关产品名称属于各自权利人。本项目不是华为官方产品，不暗示合作或认证。接口名称用于互操作，不赋予访问他人数据或绕过访问控制的权限。

浏览器配对使用 [Playwright](https://github.com/microsoft/playwright)（Apache-2.0）及其下载的 Chromium。它们不随本仓库分发；安装时应遵守各自许可。核心采集、存储、查询仅使用 Python 标准库。
