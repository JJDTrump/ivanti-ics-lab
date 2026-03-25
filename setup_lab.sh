#!/bin/bash
#
# Ivanti Connect Secure QEMU Lab Setup Script
#
# 自动化搭建 Ivanti ICS 安全研究靶场环境
# 功能：VMDK 转换 → QEMU 启动 → 自动完成初始配置
#
# 用法:
#   ./setup_lab.sh <vmdk_file> [admin_password]
#
# 示例:
#   ./setup_lab.sh ISA-V-VMWARE-22.7r2.3-b3431.vmdk MyP@ssw0rd
#

set -euo pipefail

# ============================================================
# 配置参数
# ============================================================
RAW_DIR="/tmp"
QEMU_MEMORY="4096"
QEMU_SMP="2"
VNC_DISPLAY="1"                              # VNC 端口 = 5900 + display
VNC_ADDR="127.0.0.1"                          # VNC 绑定地址（仅内网）
MONITOR_PORT="55555"                          # QEMU Monitor TCP 端口
MONITOR_ADDR="127.0.0.1"                      # Monitor 绑定地址（仅内网）
WEB_HOST_PORT="20443"                         # 宿主机 Web 转发端口
WEB_BIND="127.0.0.1"                          # Web 端口绑定地址（仅内网）

# 网络配置（QEMU user-mode 网络）
VM_IP="10.0.2.15"
VM_MASK="255.255.255.0"
VM_GW="10.0.2.2"
VM_DNS="10.0.2.3"
VM_ADMIN_USER="admin"

# ============================================================
# 颜色输出
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }
step()  { echo -e "${BLUE}[*]${NC} $*"; }

# ============================================================
# 依赖检查
# ============================================================
check_deps() {
    local missing=0
    for cmd in qemu-system-x86_64 qemu-img socat; do
        if ! command -v "$cmd" &>/dev/null; then
            error "缺少依赖: $cmd"
            missing=1
        fi
    done

    if ! command -v pnmtopng &>/dev/null; then
        warn "未找到 pnmtopng (netpbm)，screendump 截图功能不可用"
        warn "安装: sudo apt install netpbm"
    fi

    if [ $missing -eq 1 ]; then
        error "请安装缺失的依赖后重试"
        echo "  sudo apt install qemu-system-x86 qemu-utils socat netpbm"
        exit 1
    fi

    # 检查 KVM
    if [ ! -e /dev/kvm ]; then
        warn "/dev/kvm 不存在，尝试加载 KVM 模块..."
        sudo modprobe kvm-intel 2>/dev/null || sudo modprobe kvm-amd 2>/dev/null || true
        if [ ! -e /dev/kvm ]; then
            error "KVM 不可用。无 KVM 的情况下安装将极其缓慢（30+ 分钟）"
            read -p "是否继续？[y/N] " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                exit 1
            fi
            KVM_OPTS=""
        else
            KVM_OPTS="-enable-kvm -cpu host"
        fi
    else
        KVM_OPTS="-enable-kvm -cpu host"
        info "KVM 加速可用"
    fi
}

# ============================================================
# QEMU Monitor 通信
# ============================================================
monitor_cmd() {
    # 向 QEMU Monitor 发送命令
    echo "$1" | socat - "tcp:${MONITOR_ADDR}:${MONITOR_PORT}" 2>/dev/null
}

send_key() {
    # 发送单个按键
    monitor_cmd "sendkey $1"
    sleep 0.15
}

send_enter() {
    send_key "ret"
    sleep 0.3
}

send_string() {
    # 将字符串逐字符转换为 sendkey 命令
    local str="$1"
    local i
    for (( i=0; i<${#str}; i++ )); do
        local ch="${str:$i:1}"
        case "$ch" in
            [a-z])  send_key "$ch" ;;
            [A-Z])  send_key "shift-$(echo "$ch" | tr '[:upper:]' '[:lower:]')" ;;
            [0-9])  send_key "$ch" ;;
            '.')    send_key "dot" ;;
            '-')    send_key "minus" ;;
            '_')    send_key "shift-minus" ;;
            '/')    send_key "slash" ;;
            ':')    send_key "shift-semicolon" ;;
            '@')    send_key "shift-2" ;;
            '!')    send_key "shift-1" ;;
            '#')    send_key "shift-3" ;;
            '$')    send_key "shift-4" ;;
            '%')    send_key "shift-5" ;;
            '^')    send_key "shift-6" ;;
            '&')    send_key "shift-7" ;;
            '*')    send_key "shift-8" ;;
            '(')    send_key "shift-9" ;;
            ')')    send_key "shift-0" ;;
            '+')    send_key "shift-equal" ;;
            '=')    send_key "equal" ;;
            ' ')    send_key "spc" ;;
            ',')    send_key "comma" ;;
            ';')    send_key "semicolon" ;;
            "'")    send_key "apostrophe" ;;
            '"')    send_key "shift-apostrophe" ;;
            '\\')   send_key "backslash" ;;
            '|')    send_key "shift-backslash" ;;
            '[')    send_key "bracket_left" ;;
            ']')    send_key "bracket_right" ;;
            '{')    send_key "shift-bracket_left" ;;
            '}')    send_key "shift-bracket_right" ;;
            '~')    send_key "shift-grave_accent" ;;
            '`')    send_key "grave_accent" ;;
            '<')    send_key "shift-comma" ;;
            '>')    send_key "shift-dot" ;;
            '?')    send_key "shift-slash" ;;
            *)      warn "无法映射字符: '$ch'，跳过" ;;
        esac
    done
}

screendump() {
    # 截取 VGA 屏幕并转换为 PNG
    local output="${1:-/tmp/ivanti_screen.png}"
    local ppm_file="/tmp/ivanti_screen_$$.ppm"
    monitor_cmd "screendump ${ppm_file}"
    sleep 0.5
    if [ -f "$ppm_file" ] && command -v pnmtopng &>/dev/null; then
        pnmtopng "$ppm_file" > "$output" 2>/dev/null
        rm -f "$ppm_file"
        info "截图已保存: $output"
    elif [ -f "$ppm_file" ]; then
        mv "$ppm_file" "${output%.png}.ppm"
        info "截图已保存 (PPM): ${output%.png}.ppm"
    else
        warn "截图失败"
    fi
}

wait_with_progress() {
    # 带进度条的等待
    local seconds=$1
    local msg="$2"
    step "$msg（等待 ${seconds} 秒）"
    local i
    for (( i=1; i<=seconds; i++ )); do
        printf "\r  [%3d/%3d] " "$i" "$seconds"
        local pct=$((i * 50 / seconds))
        printf "["
        local j
        for (( j=0; j<pct; j++ )); do printf "#"; done
        for (( j=pct; j<50; j++ )); do printf "-"; done
        printf "]"
        sleep 1
    done
    echo
}

# ============================================================
# 主流程
# ============================================================
main() {
    echo
    echo "============================================"
    echo "  Ivanti Connect Secure QEMU 靶场搭建脚本"
    echo "============================================"
    echo

    # 参数检查
    if [ $# -lt 1 ]; then
        echo "用法: $0 <vmdk_file> [admin_password]"
        echo
        echo "参数:"
        echo "  vmdk_file       Ivanti ICS VMDK 固件文件路径"
        echo "  admin_password  管理员密码（默认: Ivanti@Lab123）"
        echo
        echo "示例:"
        echo "  $0 ISA-V-VMWARE-22.7r2.3-b3431.vmdk"
        echo "  $0 ISA-V-VMWARE-22.7r2.3-b3431.vmdk 'MyP@ss!'"
        exit 1
    fi

    local VMDK_FILE="$1"
    local ADMIN_PASS="${2:-Ivanti@Lab123}"
    local RAW_FILE="${RAW_DIR}/ivanti.raw"

    if [ ! -f "$VMDK_FILE" ]; then
        error "VMDK 文件不存在: $VMDK_FILE"
        exit 1
    fi

    # ----------------------------------------------------------
    # 步骤 0：依赖检查
    # ----------------------------------------------------------
    step "检查依赖..."
    check_deps
    echo

    # ----------------------------------------------------------
    # 步骤 1：转换 VMDK → RAW
    # ----------------------------------------------------------
    if [ -f "$RAW_FILE" ]; then
        warn "RAW 文件已存在: $RAW_FILE"
        read -p "是否重新转换？[y/N] " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -f "$RAW_FILE"
        else
            info "使用已有 RAW 文件"
        fi
    fi

    if [ ! -f "$RAW_FILE" ]; then
        step "转换 VMDK 到 RAW 格式..."
        info "源文件: $VMDK_FILE"
        info "目标: $RAW_FILE"
        qemu-img convert -f vmdk -O raw "$VMDK_FILE" "$RAW_FILE"
        info "转换完成"
        ls -lh "$RAW_FILE"
    fi
    echo

    # ----------------------------------------------------------
    # 步骤 2：检查是否有残留 QEMU 进程
    # ----------------------------------------------------------
    if socat - "tcp:${MONITOR_ADDR}:${MONITOR_PORT}" </dev/null &>/dev/null; then
        warn "检测到 QEMU Monitor 端口 ${MONITOR_PORT} 已被占用"
        read -p "是否终止已有实例并继续？[y/N] " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            echo "quit" | socat - "tcp:${MONITOR_ADDR}:${MONITOR_PORT}" 2>/dev/null || true
            sleep 2
        else
            error "请先关闭已有 QEMU 实例"
            exit 1
        fi
    fi

    # ----------------------------------------------------------
    # 步骤 3：启动 QEMU
    # ----------------------------------------------------------
    step "启动 QEMU 虚拟机..."
    info "内存: ${QEMU_MEMORY}MB, vCPU: ${QEMU_SMP}"
    info "VNC: ${VNC_ADDR}:$((5900 + VNC_DISPLAY))"
    info "Monitor: ${MONITOR_ADDR}:${MONITOR_PORT}"
    info "Web 转发: ${WEB_BIND}:${WEB_HOST_PORT} -> VM:443"

    qemu-system-x86_64 \
        -m "${QEMU_MEMORY}" \
        -smp "${QEMU_SMP}" \
        ${KVM_OPTS} \
        -drive "file=${RAW_FILE},format=raw,if=none,id=disk0" \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk0,bus=ahci.0 \
        -netdev "user,id=net0,hostfwd=tcp:${WEB_BIND}:${WEB_HOST_PORT}-:443" \
        -device e1000,netdev=net0 \
        -vnc "${VNC_ADDR}:${VNC_DISPLAY}" \
        -monitor "tcp:${MONITOR_ADDR}:${MONITOR_PORT},server,nowait" \
        -daemonize \
        -pidfile /tmp/ivanti_qemu.pid

    sleep 2

    # 验证 QEMU 是否启动成功
    if ! socat - "tcp:${MONITOR_ADDR}:${MONITOR_PORT}" </dev/null &>/dev/null; then
        error "QEMU 启动失败，请检查日志"
        exit 1
    fi
    info "QEMU 启动成功 (PID: $(cat /tmp/ivanti_qemu.pid 2>/dev/null || echo 'unknown'))"
    echo

    # ----------------------------------------------------------
    # 步骤 4：等待 Factory Reset 完成
    # ----------------------------------------------------------
    wait_with_progress 600 "等待 Factory Reset 安装完成（约 10 分钟）"
    screendump /tmp/ivanti_after_install.png
    echo

    # ----------------------------------------------------------
    # 步骤 5：等待系统重启
    # ----------------------------------------------------------
    wait_with_progress 120 "等待系统重启并进入配置界面"
    screendump /tmp/ivanti_config_screen.png
    echo

    # ----------------------------------------------------------
    # 步骤 6：自动初始配置
    # ----------------------------------------------------------
    step "开始自动初始配置..."

    # 6.1 接受许可协议
    info "接受许可协议..."
    sleep 2
    send_key "y"
    sleep 0.5
    send_enter
    sleep 3

    # 6.2 配置 IP 地址
    info "配置 IP 地址: ${VM_IP}"
    send_string "$VM_IP"
    send_enter
    sleep 1

    # 6.3 配置子网掩码
    info "配置子网掩码: ${VM_MASK}"
    send_string "$VM_MASK"
    send_enter
    sleep 1

    # 6.4 配置默认网关
    info "配置默认网关: ${VM_GW}"
    send_string "$VM_GW"
    send_enter
    sleep 1

    # 6.5 配置 DNS
    info "配置 DNS: ${VM_DNS}"
    send_string "$VM_DNS"
    send_enter
    sleep 1

    # 6.6 创建管理员用户
    info "创建管理员用户: ${VM_ADMIN_USER}"
    send_string "$VM_ADMIN_USER"
    send_enter
    sleep 1

    # 6.7 设置密码
    info "设置管理员密码..."
    send_string "$ADMIN_PASS"
    send_enter
    sleep 1

    # 6.8 确认密码
    send_string "$ADMIN_PASS"
    send_enter
    sleep 1

    # 6.9 后续确认（通常是 'y' + Enter）
    info "确认配置..."
    send_key "y"
    send_enter
    sleep 5

    screendump /tmp/ivanti_config_done.png
    echo

    # ----------------------------------------------------------
    # 步骤 7：等待服务启动
    # ----------------------------------------------------------
    wait_with_progress 60 "等待 Web 服务启动"
    echo

    # ----------------------------------------------------------
    # 完成
    # ----------------------------------------------------------
    echo
    echo "============================================"
    info "靶场搭建完成！"
    echo "============================================"
    echo
    echo "  访问信息:"
    echo "  ----------------------------------------"
    echo "  Web 管理界面:  https://${WEB_BIND}:${WEB_HOST_PORT}/dana-na/auth/url_admin/welcome.cgi"
    echo "  VNC 控制台:    ${VNC_ADDR}:$((5900 + VNC_DISPLAY))"
    echo "  QEMU Monitor:  ${MONITOR_ADDR}:${MONITOR_PORT}"
    echo "  管理员用户:    ${VM_ADMIN_USER}"
    echo "  管理员密码:    ${ADMIN_PASS}"
    echo "  ----------------------------------------"
    echo
    echo "  常用命令:"
    echo "  ----------------------------------------"
    echo "  截屏:     echo 'screendump /tmp/s.ppm' | socat - tcp:${MONITOR_ADDR}:${MONITOR_PORT}"
    echo "  关机:     echo 'quit' | socat - tcp:${MONITOR_ADDR}:${MONITOR_PORT}"
    echo "  VNC连接:  vncviewer ${VNC_ADDR}:$((5900 + VNC_DISPLAY))"
    echo "  ----------------------------------------"
    echo
    warn "所有端口仅绑定内网地址 (${WEB_BIND})，如需公网访问请自行修改"
    echo
}

main "$@"
