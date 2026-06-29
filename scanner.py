import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "desc": "HSTS 头未设置，网站可能被降级攻击",
        "fix": "添加：Strict-Transport-Security: max-age=31536000",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "desc": "缺少此头，浏览器可能错误猜测文件类型",
        "fix": "添加：X-Content-Type-Options: nosniff",
    },
    "Content-Security-Policy":{
        "severity":"medium",
        "desc":'缺了的话无法防御 XSS',
        "fix":"添加Content-Security-Policy: default-src 'self",
    },
    "X-Frame-Options":{
        "severity":"low",
        "desc":"缺了的话页面可能被嵌到钓鱼网站的 iframe 里 ",
        "fix":"X-Frame-Options: DENY",
    },
    "X-XSS-Protection":{
        "severity":"low",
        "desc":"缺少旧浏览器 XSS 防护层",
        "fix":"修复X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy":{
        "severity":"low",
        "desc":"缺少此头，跳转时可能泄漏敏感 URL",
        "fix":"Referrer-Policy: strict-origin-when-cross-origin",
    },
      "Permissions-Policy":{
        "severity":"low",
        "desc": "未限制浏览器 API 使用",
        "fix":"修复Permission-Policy:camera=(),microphone=(),geolocation()",
      },
}


def check_headers(target_url):
    results = []
    try:
        resp = requests.get(target_url, timeout=8)
        for header, info in SECURITY_HEADERS.items():
            if header not in resp.headers:
                results.append({
                    "name": header,
                    "severity": info["severity"],
                    "desc": info["desc"],
                    "fix": info["fix"],
                })
        return results
    except Exception as e:
        return {"error": str(e)}

EXPOSED_PATHS = [
    "/robots.txt",
    "/.git/HEAD",
    "/.env",
    "/admin/",
]

def check_exposed_files(target_url):
    findings = []
    for path in EXPOSED_PATHS:
        full_url = target_url.rstrip("/") + path
        try:
            resp = requests.get(full_url, timeout=5)
            if resp.status_code == 200:
                findings.append({"path": path, "url": full_url})
        except:
            pass
    return findings



def summarize(findings):
    counts = {}
    for r in findings:
        severity = r["severity"]
        if severity not in counts:
            counts[severity] = 0
        counts[severity] = counts[severity] + 1
    return counts


SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR '1'='1' --",
    '" OR "1"="1',
    "' UNION SELECT 1--",
]

SQLI_ERROR_SIGNATURES = [
    "SQL syntax",
    "You have an error in your SQL",
    "mysql_fetch",
    "Uncaught mysqli",
    "Warning: mysql",
    "syntax error",
    "ORA-",
    "Incorrect syntax near",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
]

def check_xss(target_url):
    result = []
    for payload in XSS_PAYLOADS[:2]:
        safe_url = target_url + "?q=" + requests.utils.quote(payload)
        try:
            resp = requests.get(safe_url, timeout=5)
            if payload in resp.text:
                result.append({"type": "反射型 XSS",
                    "severity": "high",
                    "payload": payload,
                    "url": safe_url,
})
                break
        except:
            continue
    return result

def check_sqli(target_url):
    result = []
    for payload in SQLI_PAYLOADS:
        try:
            safe_url = target_url +"?id=" + requests.utils.quote(payload)
            resp = requests.get(safe_url,timeout=5)
            for sig in SQLI_ERROR_SIGNATURES:
                if sig.lower() in resp.text.lower():
                 result.append({"type":"注入型",
                                "severity":"high",
                                "payload":payload,
                                "signature":sig,
                                "url":safe_url,
})
                 break
        except:
                continue
    return result


COMMON_PORTS = [80, 443, 22, 3306, 8080]


def check_open_ports(target_url):
    result  = []
    for port in COMMON_PORTS:
        full_url = target_url + ":" + str(port)
        try:
            resp = requests.get(full_url, timeout=2)
            result.append({"port": port, "status": "open"})
        except:
            pass
    return result
    

def check_cookie_flags(target_url):
    result = []
    try:
        resp = requests.get(target_url,timeout=3)
        Set_Cookie = resp.headers.get("Set-Cookie","")
        if "HttpOnly" not in Set_Cookie:
             result.append({"flag": "HttpOnly", "status": "missing"})
        if "Secure" not in Set_Cookie:
            result.append({"flag":"Secure", "Status":"missing"})
    except:
        pass
    return result




        