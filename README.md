🛡️ UnauthCheck

🚀 介绍
这是一个用于 HTTP 头认证绕过 & JWT 渗透测试 的 Fuzzing 工具，能够快速检测 未授权访问漏洞，并支持 爆破模式。



📌 支持功能：
✅ JWT 认证绕过 （无签名 JWT、伪造 Token、kid SQL 注入）
✅ 冷门 HTTP 头认证 （X-Auth-Token、X-API-Key、Proxy-Authorization 等）
✅ HTTP 头大小写绕过 （authorization: Bearer null vs AUTHORIZATION: Bearer null）
✅ 伪造 X-Forwarded-* 头 （X-Forwarded-For: 127.0.0.1、X-Original-URL: /admin）
✅ 两种模式：默认 未授权测试，支持 爆破模式
✅ 无需额外依赖（不使用 PyJWT，手动构造 JWT）


🔧 安装 & 运行
git clone https://github.com/yourusername/http-auth-bypass.git
cd http-auth-bypass
python3 http_fuzzer.py -u http://example.com/admin


📌 使用示例
🔹 1. HTTP 头未授权访问测试
bash
复制
编辑
python3 http_fuzzer.py -u http://example.com/admin
🔹 自动测试 JWT 认证绕过
🔹 测试冷门 HTTP 头认证
🔹 测试 X-Forwarded-* 伪造绕过


🔹 2. HTTP 认证爆破
bash
复制
编辑
python3 http_fuzzer.py -u http://example.com/login -m brute
🔹 支持用户名 & 口令字典
🔹 支持 Basic & Bearer 爆破


🛠️ 参数

参数	说明	默认值
-u / --url	目标 URL	必填
-m / --mode	模式 (unauthorized / brute)	unauthorized
--method	HTTP 方法 (GET / POST / PUT / DELETE)	GET
📢 免责声明
本工具仅供安全研究和渗透测试用途，禁止非法使用！⚠️ 请在合法授权的前提下使用本工具，否则后果自负。

👨‍💻 贡献 & 反馈
如果你有任何建议或改进，欢迎 PR 和 Issue！🎉
