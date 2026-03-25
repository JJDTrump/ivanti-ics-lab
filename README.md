# Ivanti Connect Secure (ICS) 安全研究靶场搭建指南

> Ivanti Connect Secure 固件解密与 QEMU 靶场环境搭建完整文档。
> 覆盖固件结构逆向、三层加密解密、QEMU 虚拟化运行及安全态势分析。

## 支持版本

| 版本 | Build | 文件名 | 说明 |
|------|-------|--------|------|
| 22.7R2.3 | b3431 | ps-ics-vmware-isa-v-22.7r2.3-b3431-package.zip | CVE-2025-22457 修复前 |
| 22.7R2.8 | b4471 | ps-ics-vmware-isa-v-22.7r2.8-b4471-package.zip | CVE-2025-22457 修复后 |
| 22.8R2.2 | b18481 | ps-ics-vmware-isa-v-22.8r2.2-b18481-package.zip | 最新分支，架构迁移 |

---

## 1. 固件结构

### 1.1 固件包层次

```
ZIP 包
├── ISA-V-VMWARE-*.ovf          # VMware 虚拟机描述文件
└── ISA-V-VMWARE-*.vmdk         # streamOptimized VMDK（虚拟大小 80GB，实际 ~2GB）
```

### 1.2 磁盘分区布局

```
/dev/sda
├── sda1  102MB  ext3  Boot Partition 1 (GRUB + Kernel + coreboot.img)
├── sda2  102MB  ext3  Boot Partition 2 (备用启动分区)
├── sda3  102MB  ext3  Boot Partition 3 (备用启动分区)
└── sda4  扩展分区
    └── sda5  LVM + LUKS
        ├── groupZ/home     # 系统数据 + package.pkg
        ├── groupZ/runtime  # 运行时数据
        └── groupZ/swap     # 交换分区
```

### 1.3 启动分区内容

```
/boot
├── grub/
│   ├── grub.conf           # GRUB 配置（含硬编码密码）
│   └── stage2              # GRUB Stage2
├── bzImage                 # Linux 内核 4.17.x
├── coreboot.img            # 加密的 initramfs（AES-128 自定义模式）
└── VERSION                 # 版本信息文件
```

### 1.4 引导流程

```
GRUB → bzImage (kernel 4.17.x) → 解密 coreboot.img → initramfs
→ LVM 初始化 → LUKS 解密 → 挂载文件系统 → 解密 package.pkg → 安装系统
→ chroot → /sbin/init
```

---

## 2. 固件解密流程

### 2.1 Initramfs 解密（coreboot.img）

Ivanti 使用自定义 AES-128 加密模式保护 initramfs。解密流程如下：

#### 步骤 1：提取 vmlinux

```bash
# 从 bzImage 提取原始 vmlinux
scripts/extract-vmlinux bzImage > vmlinux

# 使用 vmlinux-to-elf 恢复符号表（推荐）
pip install vmlinux-to-elf
vmlinux-to-elf vmlinux vmlinux-syms.elf
```

#### 步骤 2：提取加密密钥

从 vmlinux ELF 中提取关键数据：

1. **AES 密钥**：从 `DSRAMFS_AES_KEY` 符号位置读取 16 字节原始密钥
2. **XOR 混淆常量**：从 `populate_rootfs()` 函数反汇编中提取 4 个 32 位常量
   - 搜索 `xor $IMM32, %edx` (opcode: `81 f2 XX XX XX XX`)
   - 搜索 `xor $IMM32, %esi` (opcode: `81 f6 XX XX XX XX`)
   - 搜索 `xor $IMM32, %eax` (opcode: `35 XX XX XX XX`)
3. **密钥去混淆**：将原始密钥按两个 QWORD 拆分，分别与 4 个常量 XOR 得到真实 AES-128 密钥

**22.7R2.3 版本密钥数据示例**：

```
原始密钥:    13d7b32e2600b7747d80fba8f8d5c7ca
XOR 常量:    0x99ed2bf2, 0xaeef41fe, 0x141058c7, 0xd2ed180e
派生 AES 密钥: e1fc5eb7d84158dabad8ebbcf6cd2a18
```

#### 步骤 3：AES-128 自定义模式解密

**算法描述**（经内核反汇编验证）：

```
以 AES-128 ECB 为基础构建块，数据按 512 字节扇区处理：

对每个 512 字节扇区 (sector_num = 0, 1, 2, ...):
    1. keystream = AES_Decrypt(sector_counter)
       sector_counter = [sector_num, 0, 0, 0]（16字节小端）
       注意：keystream 在每个扇区只生成一次，所有块共用

    2. counter = sector_counter  （初始化链式计数器）

    3. 对扇区内每个 16 字节块:
       intermediate = ciphertext XOR keystream      # 与扇区 keystream 异或
       result = AES_Decrypt(intermediate)            # AES-128 ECB 解密
       plaintext = result XOR counter                # 与链式计数器异或
       counter = intermediate                        # 链式更新
```

**关键细节**：keystream 在每个扇区只生成**一次**（不是每个块），这是通过跳转指令 `jmp 0x08eb` 跳过第一次 AES 调用实现的。

#### 步骤 4：解压 initramfs

```bash
# 使用解密工具
python3 ivanti_fw_decrypt.py vmlinux-syms.elf coreboot.img coreboot.dec

# 解密输出为 gzip 压缩的 cpio 归档
zcat coreboot.dec | cpio -idm -D ./initramfs/
```

### 2.2 LUKS 分区解密

LVM 卷使用 LUKS 加密，密钥在 initramfs 中明文存储：

```
加密算法:  aes-cbc-essiv:sha256
密钥文件:  /etc/lvmkey（initramfs 根目录，16 字节）
密钥内容:  6e1bd1c34870bd72d231bd75537e6cc3
```

解密 LUKS 分区：

```bash
# 挂载 LUKS
cryptsetup luksOpen --key-file ./initramfs/etc/lvmkey /dev/sda5 ivanti_crypt

# 激活 LVM
vgscan
vgchange -ay groupZ

# 挂载
mount /dev/groupZ/home /mnt/home
mount /dev/groupZ/runtime /mnt/runtime
```

### 2.3 Package 双层解密

`package.pkg` 位于 `groupZ/home` 分区，经过两层加密：

```
package.pkg
  → 第一层: packdecrypt（32位ELF，RSA签名验证 + AES解密 via EVP_BytesToKey）
    → new-pack.tar.gz
      → 第二层: installer/packdecrypt（静态链接版本）
        → system.tar.xz
          → 完整 ICS 系统文件（~3GB）
```

**packdecrypt 特征**：
- 32 位 ELF，无 Canary，无 PIE
- 内嵌 2 个 RSA-2048 公钥
- 使用 OpenSSL EVP_BytesToKey 派生 AES 密钥

---

## 3. QEMU 靶场搭建

### 3.1 前提条件

```bash
# 必需软件
sudo apt install qemu-system-x86 qemu-utils socat netpbm

# 检查 KVM 支持
ls -la /dev/kvm
# 如果不存在，加载模块：
sudo modprobe kvm-intel  # 或 kvm-amd
```

### 3.2 步骤 1：转换 VMDK 到 RAW

Ivanti 提供的 VMDK 是 streamOptimized 格式，QEMU 无法直接启动，必须转换为 RAW：

```bash
qemu-img convert -f vmdk -O raw ISA-V-VMWARE-*.vmdk /tmp/ivanti.raw
```

> 注意：转换后的 RAW 文件约 80GB（虚拟大小），但大部分是零填充，实际占用空间取决于文件系统是否支持稀疏文件。

### 3.3 步骤 2：启动 QEMU

```bash
qemu-system-x86_64 \
  -m 4096 \
  -smp 2 \
  -enable-kvm \
  -cpu host \
  -drive file=/tmp/ivanti.raw,format=raw,if=none,id=disk0 \
  -device ahci,id=ahci \
  -device ide-hd,drive=disk0,bus=ahci.0 \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:20443-:443 \
  -device e1000,netdev=net0 \
  -vnc 127.0.0.1:1 \
  -monitor tcp:127.0.0.1:55555,server,nowait
```

**参数说明**：

| 参数 | 说明 |
|------|------|
| `-m 4096` | 分配 4GB 内存 |
| `-smp 2` | 2 个 vCPU |
| `-enable-kvm -cpu host` | KVM 硬件加速（必须） |
| `-device ahci` | AHCI SATA 控制器（必须，Ivanti 内核仅内置 ahci 驱动） |
| `-device ide-hd,bus=ahci.0` | 将磁盘挂载到 AHCI 总线 |
| `hostfwd=tcp:127.0.0.1:20443-:443` | 将宿主机 20443 端口转发到虚拟机 443 |
| `-vnc 127.0.0.1:1` | VNC 服务监听 127.0.0.1:5901 |
| `-monitor tcp:127.0.0.1:55555` | QEMU Monitor 监听 127.0.0.1:55555 |

### 3.4 步骤 3：初始配置

首次启动时，系统会进行 Factory Reset 安装（约 10-15 分钟），完成后自动重启。

重启后进入配置界面，需要通过 VGA 控制台完成以下配置：

```bash
# 通过 QEMU Monitor 发送按键（使用 socat）
MONITOR="tcp:127.0.0.1:55555"

# 等待出现 "Current" 提示后...

# 1. 接受许可协议
echo "sendkey y" | socat - $MONITOR
sleep 0.3
echo "sendkey ret" | socat - $MONITOR

# 2. 配置网络 - IP 地址
# 输入: 10.0.2.15
for key in 1 0 dot 0 dot 2 dot 1 5; do
  echo "sendkey $key" | socat - $MONITOR
  sleep 0.1
done
echo "sendkey ret" | socat - $MONITOR

# 3. 子网掩码: 255.255.255.0
for key in 2 5 5 dot 2 5 5 dot 2 5 5 dot 0; do
  echo "sendkey $key" | socat - $MONITOR
  sleep 0.1
done
echo "sendkey ret" | socat - $MONITOR

# 4. 默认网关: 10.0.2.2
for key in 1 0 dot 0 dot 2 dot 2; do
  echo "sendkey $key" | socat - $MONITOR
  sleep 0.1
done
echo "sendkey ret" | socat - $MONITOR

# 5. DNS 服务器: 10.0.2.3
for key in 1 0 dot 0 dot 2 dot 3; do
  echo "sendkey $key" | socat - $MONITOR
  sleep 0.1
done
echo "sendkey ret" | socat - $MONITOR

# 6. 创建管理员账户（用户名: admin）
for key in a d m i n; do
  echo "sendkey $key" | socat - $MONITOR
  sleep 0.1
done
echo "sendkey ret" | socat - $MONITOR

# 7. 设置密码（根据需要修改）
# ... 输入密码字符 ...
echo "sendkey ret" | socat - $MONITOR

# 8. 确认密码
# ... 再次输入密码 ...
echo "sendkey ret" | socat - $MONITOR

# 后续步骤：生成自签名 SSL 证书等，按提示操作
```

**获取 VGA 控制台截图**（用于确认当前界面状态）：

```bash
# 通过 QEMU Monitor 截取屏幕
echo "screendump /tmp/screen.ppm" | socat - tcp:127.0.0.1:55555
# 转换为 PNG
pnmtopng /tmp/screen.ppm > /tmp/screen.png
```

### 3.5 关键注意事项

1. **必须使用 AHCI 控制器**
   - Ivanti 内核 (4.17.x) 内置 ahci 驱动，不支持 IDE (`-hda`) 或 virtio-scsi
   - 使用 `-hda` 会导致内核找不到磁盘，无法启动

2. **必须启用 KVM 加速**
   - 无 KVM 的纯软件模拟下，Factory Reset 安装需要 30 分钟以上
   - 启用 KVM 后约 10-15 分钟完成

3. **必须使用 RAW 磁盘格式**
   - streamOptimized VMDK 格式不能被 QEMU 直接启动
   - 必须先用 `qemu-img convert` 转换为 RAW

4. **初始配置必须通过 VGA 控制台**
   - Ivanti 串口控制台 (`-serial`) 无输出
   - 必须通过 VNC 或 QEMU Monitor sendkey 进行配置
   - 推荐使用 `screendump` 命令获取 VGA 截图确认状态

5. **网络配置**
   - QEMU user-mode 网络默认网关为 10.0.2.2
   - 虚拟机内部 IP 设置为 10.0.2.15（user-mode 网络的 DHCP 范围内）
   - DNS 使用 10.0.2.3（QEMU 内置 DNS 代理）

### 3.6 配置完成后访问

```bash
# Web 管理界面
https://127.0.0.1:20443/dana-na/auth/url_admin/welcome.cgi

# VNC 控制台
vncviewer 127.0.0.1:5901
```

---

## 4. 安全发现

### 4.1 固件加密弱点

| 发现 | 风险等级 | 说明 |
|------|----------|------|
| GRUB 密码硬编码 | 低 | 密码 `07ow3w3d743` 写死在 grub.conf 中 |
| LUKS 密钥明文存储 | 高 | `/etc/lvmkey` 在 initramfs 中未加密，解密 initramfs 即可获取 |
| AES 密钥 XOR 混淆 | 中 | 仅使用简单 XOR 混淆，非真正加密保护 |
| packdecrypt 无保护 | 中 | 32位 ELF，无 Canary/PIE，RSA 公钥内嵌 |

### 4.2 二进制安全态势

#### 22.7R2.3（修复前）

| 二进制 | 大小 | PIE | Canary | NX | RELRO | 备注 |
|--------|------|-----|--------|----|-------|------|
| web | 1.5MB | Yes | **NO** | Yes | Partial | HTTP 核心处理 |
| cgi-server | - | No | **NO** | Yes | Partial | CGI 请求处理 |
| dswsd | - | No | **NO** | Yes | Partial | Web 服务守护进程 |

> **所有关键服务均无栈保护 (Stack Canary)**，栈溢出可直接利用。

#### 22.7R2.8（修复后）

- 全部重新编译，启用 **Canary + FORTIFY + Full RELRO**
- 安全编译选项全面加固

#### 22.8R2.2（最新分支）

| 二进制 | 大小 | PIE | Canary | NX | RELRO | 攻击面 |
|--------|------|-----|--------|----|-------|--------|
| nginx | 928K | Yes | Yes | Yes | Full | HTTP 前端 |
| cgi-server | - | Yes | Yes | Yes | Full | CGI 处理 |
| **saml-server** | **2.1MB** | **NO** | **NO** | Yes | Partial | **SAML 断言处理（预认证！）** |
| **browse-server** | - | **NO** | **NO** | Yes | Partial | 文件浏览 |
| dsagentd | - | Yes | Yes | Yes | Partial | Agent 守护进程 |

> **saml-server** 是最高价值目标：预认证可达、无 Canary、无 PIE（基址 0x8048000），使用 strcpy/sprintf/popen/execv，处理 SAML XML（xerces-c 3.2 + libxmltooling）。

### 4.3 版本对比发现（R2.3 → R2.8）

| 变更 | 说明 |
|------|------|
| `canonicalizeIP` | 从 3 字节桩函数（直接 ret）扩展为 448 字节完整实现（**CVE-2025-22457 修复**） |
| `isValidClientAttrVal` | 新增函数（**CVE-2025-0282 修复**） |
| `isValidIpFormat` | 新增 IP 格式验证函数 |
| `DSCSProxyHandler::checkAccess` | 增加 3778 字节访问控制逻辑 |
| URL 重写 | 新增 "Buffer end overrun risk" 检查 |
| EAP 处理 | 新增 EAP 报文验证 |
| 编译选项 | 全面启用 Canary + FORTIFY + Full RELRO |

### 4.4 22.8R2.2 架构变化

- 前端迁移到 **nginx + 自定义模块**（取代原有 web 二进制）
- 新增 saml-server 独立进程处理 SAML
- saml-server 编译时**未启用 Canary 和 PIE**，是潜在零日目标

---

## 5. 工具说明

### 5.1 ivanti_fw_decrypt.py

固件 initramfs（coreboot.img）解密工具。

**依赖**：

```bash
pip install pycryptodome
# 系统工具
apt install binutils  # readelf
```

**用法**：

```bash
python3 ivanti_fw_decrypt.py <vmlinux_or_syms_elf> <coreboot.img> <output>
```

**参数说明**：

| 参数 | 说明 |
|------|------|
| `vmlinux_or_syms_elf` | 原始 vmlinux 或 vmlinux-to-elf 生成的带符号 ELF |
| `coreboot.img` | 启动分区中的加密 initramfs |
| `output` | 解密输出路径（gzip 压缩的 cpio 归档） |

**完整解密流程**：

```bash
# 1. 从固件包提取 VMDK
unzip ps-ics-vmware-isa-v-22.7r2.3-b3431-package.zip

# 2. 挂载 VMDK 提取启动分区文件
# （使用 guestmount / losetup + kpartx / qemu-nbd）

# 3. 提取 vmlinux
scripts/extract-vmlinux bzImage > vmlinux
vmlinux-to-elf vmlinux vmlinux-syms.elf

# 4. 解密 initramfs
python3 ivanti_fw_decrypt.py vmlinux-syms.elf coreboot.img coreboot.dec

# 5. 解压
mkdir initramfs && cd initramfs
zcat ../coreboot.dec | cpio -idm
```

### 5.2 setup_lab.sh

自动化 QEMU 靶场搭建脚本。

**用法**：

```bash
chmod +x setup_lab.sh
./setup_lab.sh <vmdk_file> [admin_password]
```

**功能**：
- 自动检查依赖和 KVM 支持
- 转换 VMDK 到 RAW 格式
- 启动 QEMU（KVM + AHCI + VNC + Monitor）
- 等待 Factory Reset 完成
- 通过 QEMU Monitor sendkey 自动完成初始配置
- 输出访问信息

---

## 6. 参考资料

- [CVE-2025-22457](https://nvd.nist.gov/vuln/detail/CVE-2025-22457) - Ivanti Connect Secure 栈溢出漏洞
- [CVE-2025-0282](https://nvd.nist.gov/vuln/detail/CVE-2025-0282) - Ivanti Connect Secure 预认证远程代码执行
- [QEMU 文档](https://www.qemu.org/docs/master/) - QEMU 系统模拟器
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) - 内核符号恢复工具

---

## 许可证

本项目仅用于授权安全研究。使用者应确保遵守相关法律法规及厂商授权协议。
