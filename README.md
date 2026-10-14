# AI 安全助手

🔗 **在线体验**：https://ai-security-assistant-toi6.onrender.com/static/index.html

## 介绍

基于 FastAPI + DeepSeek API 的 Web 安全扫描平台。输入一个网址，自动检测 10 类常见安全问题，并集成 AI 对话辅助分析。

- 后端使用 asyncio 异步并发调度全部检测模块，扫描耗时从 51 秒降至 11 秒（约 4.6 倍），并实现模块级超时控制与错误隔离，单个模块异常不影响整体。
- 前端用原生 JavaScript 实现卡片式结果展示、扫描进度反馈与暗色模式。

## 技术栈
后端 Python + FastAPI，前端 HTML + CSS + JavaScript，AI DeepSeek API，安全扫描 requests库

## 功能
- 安全头检测
- 敏感文件泄露检测
- XSS 漏洞检测
- SQL 注入检测
- 开放端口检测
- Cookie 安全检测
- 开放式重定向检测
- 目录遍历检测
- CORS 跨域检测
- HTTP 危险方法检测（PUT/DELETE）

## 本地运行

1. 安装依赖：`pip install -r requirements.txt`
2. 在项目根目录建 `.env` 文件，写入：`DEEPSEEK_API_KEY=你的key`
3. 启动：`uvicorn server:app --reload`
4. 打开 http://127.0.0.1:8000/static/index.html

## 已知限制

- 仅检测 Web **配置层面**的常见问题（缺失的安全头、暴露的文件、反射型注入等），不做业务逻辑漏洞（越权、逻辑绕过）检测。
- 检测使用公开 payload 和特征匹配，可能有误报/漏报，不能替代专业渗透测试。
- 部署在 Render 免费版，闲置后冷启动约需 30-50 秒。

## 截图
![](screenshot-new.png)