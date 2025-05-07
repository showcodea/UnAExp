🛡️ UnauthCheck

一个用于测试 HTTP 头部未授权访问和 JWT 漏洞的 Python 工具，支持两种模式：

unauthorized：模拟常见的认证绕过方式，检测未授权访问漏洞。

brute：使用 header.txt 中的 HTTP 头部名称进行爆破测试,通过冷门http头进行绕过限制。

🧰 功能特性
支持伪造无签名的 JWT Token。

支持 JWT kid 参数的 SQL 注入测试。

支持常见的认证头部测试，如 Authorization、X-API-Key 等。

支持自定义头部名称进行爆破测试。

📦 安装方法
确保已安装 Python 3。

安装依赖库：

pip install -r requirements.txt
如果没有 requirements.txt 文件，请手动安装所需库：

pip install requests
🚀 使用说明
未授权访问模式
测试常见的认证绕过方式：

python script.py -u http://example.com -m unauthorized
爆破模式
使用 header.txt 中的头部名称进行爆破测试：


python script.py -u http://example.com -m brute
如果 header.txt 文件位于其他路径，可以使用 --header-file 参数指定：


python script.py -u http://example.com -m brute --header-file /path/to/header.txt
其他参数
--method：指定 HTTP 请求方法，支持 GET、POST、PUT、DELETE，默认为 GET。

📄 示例

python script.py -u http://localhost:8080/admin -m brute --method POST
📝 header.txt 文件格式
header.txt 文件应包含每行一个 HTTP 头部名称，例如：

X-Custom-Header
X-Test-Header
Authorization

📢 免责声明

本工具仅供安全研究和渗透测试用途，禁止非法使用！⚠️ 请在合法授权的前提下使用本工具，否则后果自负。

👨‍💻 贡献 & 反馈

如果你有任何建议或改进，欢迎 PR 和 Issue！🎉
