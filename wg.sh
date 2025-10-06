#!/bin/bash

echo "
WireGuard 安装脚本
==========================
作者：xa(二改汉化版本)
"
>/etc/systemd/resolved.conf
if [[ ! -f ./wg.txt ]]; then
  echo "1" >./wg.txt
fi

if [[ $(cat ./wg.txt) -eq 1 ]]; then
  systemctl stop systemd-resolved #停用systemd-resolved服务
  ping -c1 www.google.com &>/dev/null
  if [ $? == 0 ]; then # 判断是否能ping通
    mv /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bak
    echo "备份系统DNS配置成功>> 目录/etc/systemd/resolved.conf.bak"
    echo "当前服务器可以正常访问外网>>DNS配置1.1.1.1"
    echo "
      [Resolve]
    DNS=1.1.1.1  #国外DNS
    DNSStubListener=no
" >>/etc/systemd/resolved.conf

    echo "2" >./wg.txt
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    iptables -I INPUT -p UDP --dport 53 -j ACCEPT
  else
    mv /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bak
    echo "备份系统DNS配置成功>> 目录/etc/systemd/resolved.conf.bak"
    echo "当前服务器无法正常访问外网>>DNS配置223.5.5.5"
    echo "
     [Resolve]
    DNS=223.5.5.5  #国内DNS
    DNSStubListener=no
" >>/etc/systemd/resolved.conf
    echo "2" >./wg.txt
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    iptables -I INPUT -p UDP --dport 53 -j ACCEPT
  fi
fi

# 错误退出函数：输出错误信息并退出（状态码1）
exiterr() {
  echo "错误：$1" >&2
  exit 1
}
# 错误退出函数：apt-get安装失败时调用
exiterr2() { exiterr "'apt-get install' 命令执行失败。"; }
# 错误退出函数：yum安装失败时调用
exiterr3() { exiterr "'yum install' 命令执行失败。"; }
# 错误退出函数：zypper安装失败时调用
exiterr4() { exiterr "'zypper install' 命令执行失败。"; }

# 检查IP地址格式（IPv4）
check_ip() {
  # IPv4地址正则表达式
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  # 移除输入中的换行符并检查是否匹配IPv4正则
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

# 检查私有IP地址格式（IPv4）
check_pvt_ip() {
  # 私有IPv4地址段正则表达式（10.0.0.0/8、172.16.0.0/12、192.168.0.0/16、169.254.0.0/16）
  IPP_REGEX='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
  # 移除输入中的换行符并检查是否匹配私有IP正则
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IPP_REGEX"
}

# 检查DNS域名格式（完全限定域名FQDN）
check_dns_name() {
  # FQDN正则表达式（支持多级域名，后缀至少2个字符）
  FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
  # 移除输入中的换行符并检查是否匹配FQDN正则
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

# 检查是否以root用户身份运行
check_root() {
  if [ "$(id -u)" != 0 ]; then
    exiterr "此安装脚本必须以root用户身份运行。请尝试执行 'sudo bash $0'"
  fi
}

# 检查是否使用bash执行脚本（避免Debian用户用sh执行）
check_shell() {
  # 检测是否通过dash（sh在部分Debian系统中的链接）执行脚本
  if readlink /proc/$$/exe | grep -q "dash"; then
    exiterr "此安装脚本需使用 'bash' 执行，不可使用 'sh'。"
  fi
}

# 检查内核版本（排除OpenVZ 6的旧内核）
check_kernel() {
  # 若内核主版本为2（OpenVZ 6常见内核版本），则判定为不兼容
  if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
    exiterr "当前系统运行的内核版本过旧，与本安装脚本不兼容。"
  fi
}

# 检测操作系统类型及版本
check_os() {
  if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    # 提取Ubuntu版本号（如20.04提取为2004）
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
  elif [[ -e /etc/debian_version ]]; then
    os="debian"
    # 提取Debian主版本号（如11提取为11）
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
  elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
    os="centos"
    # 提取AlmaLinux/Rocky Linux/CentOS的主版本号
    os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
  elif [[ -e /etc/fedora-release ]]; then
    os="fedora"
    # 提取Fedora版本号
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
  elif [[ -e /etc/SUSE-brand && "$(head -1 /etc/SUSE-brand)" == "openSUSE" ]]; then
    os="openSUSE"
    # 提取openSUSE版本号（如15.4）
    os_version=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
  else
    exiterr "此安装脚本似乎运行在不支持的操作系统上。
支持的操作系统包括：Ubuntu、Debian、AlmaLinux、Rocky Linux、CentOS、Fedora 和 openSUSE。"
  fi
}

# 检查操作系统版本是否符合要求
check_os_ver() {
  # Ubuntu需20.04或更高版本
  if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
    exiterr "本安装脚本要求Ubuntu 20.04或更高版本。
当前Ubuntu版本过旧，不受支持。"
  fi
  # Debian需11或更高版本
  if [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
    exiterr "本安装脚本要求Debian 11或更高版本。
当前Debian版本过旧，不受支持。"
  fi
  # CentOS/AlmaLinux/Rocky Linux需8或更高版本
  if [[ "$os" == "centos" && "$os_version" -lt 8 ]]; then
    exiterr "本安装脚本要求CentOS 8或更高版本。
当前CentOS版本过旧，不受支持。"
  fi
}

# 检查是否在容器环境中运行（不支持容器）
check_container() {
  # 若系统在容器中运行（如Docker、LXC等），则报错退出
  if systemd-detect-virt -cq 2>/dev/null; then
    exiterr "当前系统运行在容器环境中，本安装脚本不支持容器。"
  fi
}

# 处理客户端名称（过滤特殊字符，限制长度为15字符）
set_client_name() {
  # 仅保留字母、数字、短横线（-）和下划线（_），其他字符替换为下划线
  # 截取前15个字符以兼容Linux客户端
  client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<<"$unsanitized_client" | cut -c-15)
}

# 解析命令行参数
parse_args() {
  while [ "$#" -gt 0 ]; do
    case $1 in
    --auto)
      # 自动安装模式（使用默认或自定义选项）
      auto=1
      shift
      ;;
    --addclient)
      # 添加新客户端
      add_client=1
      unsanitized_client="$2"
      shift
      shift
      ;;
    --listclients)
      # 列出所有已存在的客户端
      list_clients=1
      shift
      ;;
    --removeclient)
      # 删除指定客户端
      remove_client=1
      unsanitized_client="$2"
      shift
      shift
      ;;
    --showclientqr)
      # 显示指定客户端的QR码（用于手机客户端扫码配置）
      show_client_qr=1
      unsanitized_client="$2"
      shift
      shift
      ;;
    --uninstall)
      # 卸载WireGuard并删除所有配置
      remove_wg=1
      shift
      ;;
    --serveraddr)
      # 指定服务器地址（FQDN或IPv4）
      server_addr="$2"
      shift
      shift
      ;;
    --port)
      # 指定WireGuard监听端口
      server_port="$2"
      shift
      shift
      ;;
    --clientname)
      # 指定第一个客户端的名称
      first_client_name="$2"
      shift
      shift
      ;;
    --dns1)
      # 指定客户端的首选DNS服务器
      dns1="$2"
      shift
      shift
      ;;
    --dns2)
      # 指定客户端的备用DNS服务器
      dns2="$2"
      shift
      shift
      ;;
    -y | --yes)
      # 移除客户端或卸载时默认回答"是"
      assume_yes=1
      shift
      ;;
    -h | --help)
      # 显示帮助信息
      show_usage
      ;;
    *)
      # 未知参数，显示帮助信息并退出
      show_usage "未知参数：$1"
      ;;
    esac
  done
}

# 检查命令行参数的合法性
check_args() {
  # 若已存在WireGuard配置，不可使用--auto参数
  if [ "$auto" != 0 ] && [ -e "$WG_CONF" ]; then
    show_usage "参数无效 '--auto'。此服务器已配置WireGuard，不可重复执行自动安装。"
  fi
  # 不可同时指定多个客户端操作参数（--addclient/--listclients/--removeclient/--showclientqr）
  if [ "$((add_client + list_clients + remove_client + show_client_qr))" -gt 1 ]; then
    show_usage "参数无效。仅可指定以下参数之一：'--addclient'、'--listclients'、'--removeclient' 或 '--showclientqr'。"
  fi
  # 卸载参数（--uninstall）不可与其他参数同时使用
  if [ "$remove_wg" = 1 ]; then
    if [ "$((add_client + list_clients + remove_client + show_client_qr + auto))" -gt 0 ]; then
      show_usage "参数无效。'--uninstall' 不可与其他参数同时指定。"
    fi
  fi
  # 若未配置WireGuard，不可执行客户端相关操作
  if [ ! -e "$WG_CONF" ]; then
    st_text="需先配置WireGuard，然后才能"
    [ "$add_client" = 1 ] && exiterr "$st_text 添加客户端。"
    [ "$list_clients" = 1 ] && exiterr "$st_text 列出客户端。"
    [ "$remove_client" = 1 ] && exiterr "$st_text 删除客户端。"
    [ "$show_client_qr" = 1 ] && exiterr "$st_text 显示客户端QR码。"
    [ "$remove_wg" = 1 ] && exiterr "无法卸载WireGuard，因为此服务器尚未配置WireGuard。"
  fi
  # --clientname参数仅可在安装WireGuard时使用
  if [ "$((add_client + remove_client + show_client_qr))" = 1 ] && [ -n "$first_client_name" ]; then
    show_usage "参数无效。'--clientname' 仅可在安装WireGuard时指定。"
  fi
  # 服务器地址/端口/第一个客户端名称参数，仅可在自动安装模式（--auto）下使用
  if [ -n "$server_addr" ] || [ -n "$server_port" ] || [ -n "$first_client_name" ]; then
    if [ -e "$WG_CONF" ]; then
      show_usage "参数无效。此服务器已配置WireGuard，不可重复指定服务器信息。"
    elif [ "$auto" = 0 ]; then
      show_usage "参数无效。使用这些参数时必须指定 '--auto'（自动安装模式）。"
    fi
  fi
  # 检查添加客户端参数的合法性
  if [ "$add_client" = 1 ]; then
    set_client_name
    if [ -z "$client" ]; then
      exiterr "客户端名称无效。仅可使用单个单词，特殊字符仅支持 '-' 和 '_'。"
    elif grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
      exiterr "$client：名称无效。该客户端已存在。"
    fi
  fi
  # 检查删除/显示QR码客户端参数的合法性
  if [ "$remove_client" = 1 ] || [ "$show_client_qr" = 1 ]; then
    set_client_name
    if [ -z "$client" ] || ! grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
      exiterr "客户端名称无效，或该客户端不存在。"
    fi
  fi
  # 检查服务器地址格式（必须是FQDN或IPv4）
  if [ -n "$server_addr" ] && { ! check_dns_name "$server_addr" && ! check_ip "$server_addr"; }; then
    exiterr "服务器地址无效。必须是完全限定域名（FQDN）或IPv4地址。"
  fi
  # 检查第一个客户端名称的合法性
  if [ -n "$first_client_name" ]; then
    unsanitized_client="$first_client_name"
    set_client_name
    if [ -z "$client" ]; then
      exiterr "客户端名称无效。仅可使用单个单词，特殊字符仅支持 '-' 和 '_'。"
    fi
  fi
  # 检查服务器端口的合法性（1-65535之间的整数）
  if [ -n "$server_port" ]; then
    if [[ ! "$server_port" =~ ^[0-9]+$ || "$server_port" -gt 65535 ]]; then
      exiterr "端口无效。必须是1-65535之间的整数。"
    fi
  fi
  # 检查DNS服务器参数的合法性
  if [ -n "$dns1" ]; then
    if [ -e "$WG_CONF" ] && [ "$add_client" = 0 ]; then
      show_usage "参数无效。自定义DNS服务器仅可在安装WireGuard或添加客户端时指定。"
    fi
  fi
  # 检查DNS服务器地址格式（必须是IPv4）
  if { [ -n "$dns1" ] && ! check_ip "$dns1"; } ||
    { [ -n "$dns2" ] && ! check_ip "$dns2"; }; then
    exiterr "DNS服务器地址无效。"
  fi
  # 不可单独指定备用DNS（--dns2），需先指定首选DNS（--dns1）
  if [ -z "$dns1" ] && [ -n "$dns2" ]; then
    show_usage "DNS参数无效。指定 '--dns2' 前必须先指定 '--dns1'。"
  fi
  # 整理DNS服务器配置字符串
  if [ -n "$dns1" ] && [ -n "$dns2" ]; then
    dns="$dns1, $dns2"
  elif [ -n "$dns1" ]; then
    dns="$dns1"
  else
    ping -c1 google.com >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
      dns="1.1.1.1"
    else
      dns="233.5.5.5"
    fi
  fi
}

# 检查CentOS系统是否启用nftables（不支持nftables，需使用iptables）
check_nftables() {
  if [ "$os" = "centos" ]; then
    if grep -qs "hwdsl2 VPN脚本" /etc/sysconfig/nftables.conf ||
      systemctl is-active --quiet nftables 2>/dev/null; then
      exiterr "当前系统已启用nftables，本安装脚本不支持nftables。"
    fi
  fi
}

# 安装wget（部分Debian最小系统可能未预装wget和curl）
install_wget() {
  # 检测是否既无wget也无curl
  if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
    if [ "$auto" = 0 ]; then
      echo "本安装脚本需要wget工具。"
      read -n1 -r -p "按任意键安装wget并继续..."
    fi
    # 非交互模式安装wget
    export DEBIAN_FRONTEND=noninteractive
    (
      set -x
      apt-get -yqq update || apt-get -yqq update
      apt-get -yqq install wget >/dev/null
    ) || exiterr2
  fi
}

# 安装iproute2（提供ip命令，用于网络配置）
install_iproute() {
  if ! hash ip 2>/dev/null; then
    if [ "$auto" = 0 ]; then
      echo "本安装脚本需要iproute工具。"
      read -n1 -r -p "按任意键安装iproute并继续..."
    fi
    # 根据操作系统选择对应的包管理器安装iproute2
    if [ "$os" = "debian" ] || [ "$os" = "ubuntu" ]; then
      export DEBIAN_FRONTEND=noninteractive
      (
        set -x
        apt-get -yqq update || apt-get -yqq update
        apt-get -yqq install iproute2 >/dev/null
      ) || exiterr2
    elif [ "$os" = "openSUSE" ]; then
      (
        set -x
        zypper install iproute2 >/dev/null
      ) || exiterr4
    else
      (
        set -x
        yum -y -q install iproute >/dev/null
      ) || exiterr3
    fi
  fi
}

# 显示脚本头部信息（项目名称和地址）
show_header() {
  cat <<'EOF'

WireGuard 安装脚本
https://github.com/hwdsl2/wireguard-install
EOF
}

# 显示欢迎头部信息（交互式安装时）
show_header2() {
  cat <<'EOF'

欢迎使用 WireGuard 服务器安装脚本！
GitHub 项目地址：https://github.com/hwdsl2/wireguard-install

EOF
}

# 显示版权信息
show_header3() {
  cat <<'EOF'

版权所有 (c) 2022-2025 林松
版权所有 (c) 2020-2023 Nyr
EOF
}

# 显示帮助信息（命令行参数说明）
show_usage() {
  if [ -n "$1" ]; then
    echo "错误：$1" >&2
  fi
  show_header
  show_header3
  cat 1>&2 <<EOF

用法：bash $0 [选项]

选项：

  --addclient [客户端名称]      添加新的WireGuard客户端
  --dns1 [DNS服务器IP]         新客户端的首选DNS服务器（可选，默认：公共DNS）
  --dns2 [DNS服务器IP]         新客户端的备用DNS服务器（可选）
  --listclients                  列出所有已存在的客户端名称
  --removeclient [客户端名称]   删除指定的客户端
  --showclientqr [客户端名称]   显示指定客户端的QR码（用于手机扫码配置）
  --uninstall                    卸载WireGuard并删除所有配置文件
  -y, --yes                      移除客户端或卸载时，默认回答"是"（跳过确认）
  -h, --help                     显示此帮助信息并退出

安装选项（可选）：

  --auto                         自动安装WireGuard（使用默认或自定义选项）
  --serveraddr [DNS名称或IP]    服务器地址（必须是完全限定域名FQDN或IPv4地址）
  --port [端口号]                WireGuard监听端口（1-65535，默认：51820）
  --clientname [客户端名称]      第一个WireGuard客户端的名称（默认：client）
  --dns1 [DNS服务器IP]         第一个客户端的首选DNS服务器（默认：公共DNS）
  --dns2 [DNS服务器IP]         第一个客户端的备用DNS服务器

如需自定义更多选项，也可直接运行此脚本（不附带任何参数）。
EOF
  exit 1
}

# 显示欢迎信息（根据安装模式调整内容）
show_welcome() {
  if [ "$auto" = 0 ]; then
    show_header2
    echo "开始配置前，需要向您确认几个问题。"
    echo "若您接受默认选项，直接按回车键即可。"
  else
    show_header
    op_text=默认
    # 若指定了自定义参数（服务器地址/端口/客户端名称/DNS），则标记为自定义选项
    if [ -n "$server_addr" ] || [ -n "$server_port" ] ||
      [ -n "$first_client_name" ] || [ -n "$dns1" ]; then
      op_text=自定义
    fi
    echo
    echo "正在使用$op_text选项配置WireGuard。"
  fi
}

# 显示DNS名称注意事项（提醒用户确保DNS解析正确）
show_dns_name_note() {
  cat <<EOF

注意：请确保DNS名称 '$1'
      已正确解析到该服务器的IPv4地址。
EOF
}

# 让用户选择服务器地址类型（DNS名称或IP）
enter_server_address() {
  echo
  echo "您是否希望WireGuard VPN客户端通过DNS名称（例如vpn.example.com）"
  printf "而非IP地址连接到该服务器？[y/N] "
  read -r response
  case $response in
  [yY][eE][sS] | [yY])
    # 使用DNS名称作为服务器地址
    use_dns_name=1
    echo
    ;;
  *)
    # 使用IP地址作为服务器地址
    use_dns_name=0
    ;;
  esac
  if [ "$use_dns_name" = 1 ]; then
    # 让用户输入DNS名称并验证格式
    read -rp "请输入该必须输入完全域名：" server_addr_i
    until check_dns_name "$server_addr_i"; do
      echo "DNS名称无效。必须输入完全域名（FQDN）。"
      read -rp "请输入该VPN服务器的DNS名称：" server_addr_i
    done
    ip="$server_addr_i"
    # 显示DNS解析提醒
    show_dns_name_note "$ip"
  else
    # 自动检测服务器IP地址
    detect_ip
    # 检查是否为私有IP（若为私有IP，需确认公网IP）
    check_nat_ip
  fi
}

# 从公网API获取服务器公网IP
find_public_ip() {
  # 用于获取公网IP的API地址
  ip_url1="http://ipv4.icanhazip.com"
  ip_url2="http://ip1.dynupdate.no-ip.com"
  # 尝试从第一个API获取公网IP，失败则尝试第二个
  get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<<"$(wget -T 10 -t 1 -4qO- "$ip_url1" || curl -m 10 -4Ls "$ip_url1")")
  if ! check_ip "$get_public_ip"; then
    get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<<"$(wget -T 10 -t 1 -4qO- "$ip_url2" || curl -m 10 -4Ls "$ip_url2")")
  fi
}

# 自动检测服务器IP地址
detect_ip() {
  # 若系统仅存在一个IPv4地址，直接使用该地址
  if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
    ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
  else
    # 从默认路由中提取IP地址
    ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
    if ! check_ip "$ip"; then
      # 若默认路由提取失败，从公网API获取公网IP
      find_public_ip
      ip_match=0
      if [ -n "$get_public_ip" ]; then
        # 列出系统所有非本地IPv4地址
        ip_list=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
        # 检查公网IP是否在系统IP列表中
        while IFS= read -r line; do
          if [ "$line" = "$get_public_ip" ]; then
            ip_match=1
            ip="$line"
          fi
        done <<<"$ip_list"
      fi
      # 若公网IP不在系统列表中，让用户手动选择
      if [ "$ip_match" = 0 ]; then
        if [ "$auto" = 0 ]; then
          echo
          echo "请选择要使用的IPv4地址："
          # 统计系统非本地IPv4地址数量
          num_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
          # 列出所有IPv4地址并编号
          ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
          read -rp "IPv4地址 [1]：" ip_num
          # 验证用户输入的编号合法性
          until [[ -z "$ip_num" || "$ip_num" =~ ^[0-9]+$ && "$ip_num" -le "$num_of_ip" ]]; do
            echo "$ip_num：选择无效。"
            read -rp "IPv4地址 [1]：" ip_num
          done
          # 若用户未输入，默认选择第一个
          [[ -z "$ip_num" ]] && ip_num=1
        else
          # 自动模式下默认选择第一个IP
          ip_num=1
        fi
        # 根据编号提取对应的IP地址
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_num"p)
      fi
    fi
  fi
  # 若IP检测失败，报错退出
  if ! check_ip "$ip"; then
    echo "错误：无法检测该服务器的IP地址。" >&2
    echo "已中止。未修改任何系统配置。" >&2
    exit 1
  fi
}

# 检查服务器IP是否为私有IP（若为私有IP，需确认公网IP）
check_nat_ip() {
  # 若检测到的IP是私有IP，说明服务器在NAT后，需获取公网IP
  if check_pvt_ip "$ip"; then
    find_public_ip
    if ! check_ip "$get_public_ip"; then
      if [ "$auto" = 0 ]; then
        echo
        echo "该服务器位于NAT之后，请输入其公网IPv4地址："
        read -rp "公网IPv4地址：" public_ip
        # 验证公网IP格式
        until check_ip "$public_ip"; do
          echo "输入无效。"
          read -rp "公网IPv4地址：" public_ip
        done
      else
        echo "错误：无法检测该服务器的公网IP。" >&2
        echo "已中止。未修改任何系统配置。" >&2
        exit 1
      fi
    else
      # 使用从API获取的公网IP
      public_ip="$get_public_ip"
    fi
  fi
}

# 显示配置信息（自动安装模式下）
show_config() {
  if [ "$auto" != 0 ]; then
    echo
    if [ -n "$server_addr" ]; then
      echo "服务器地址：$server_addr"
    else
      printf '%s' "服务器IP："
      [ -n "$public_ip" ] && printf '%s\n' "$public_ip" || printf '%s\n' "$ip"
    fi
    # 显示端口信息（自定义或默认）
    [ -n "$server_port" ] && port_text="$server_port" || port_text=51820
    # 显示第一个客户端名称（自定义或默认）
    [ -n "$first_client_name" ] && client_text="$client" || client_text=client
    # 显示DNS服务器信息（自定义或默认）
    if [ -n "$dns1" ] && [ -n "$dns2" ]; then
      dns_text="$dns1, $dns2"
    elif [ -n "$dns1" ]; then
      dns_text="$dns1"
    else
      dns_text="公共DNS"
    fi
    echo "端口：UDP/$port_text"
    echo "客户端名称：$client_text"
    echo "客户端DNS：$dns_text"
  fi
}

# 检测服务器是否支持IPv6（若支持，配置IPv6隧道）
detect_ipv6() {
  ip6=""
  # 检查系统是否存在全局可路由的IPv6地址（以2或3开头）
  if [[ $(ip -6 addr | grep -c 'inet6 [23]') -ne 0 ]]; then
    ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n 1p)
  fi
}

# 选择WireGuard监听端口（交互式或自动模式）
select_port() {
  if [ "$auto" = 0 ]; then
    echo
    echo "请选择WireGuard的监听端口："
    read -rp "端口 [51820]：" port
    # 验证端口合法性（空或1-65535的整数）
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
      echo "$port：端口无效。"
      read -rp "端口 [51820]：" port
    done
    # 若用户未输入，使用默认端口51820
    [[ -z "$port" ]] && port=51820
  else
    # 自动模式下，使用自定义端口或默认端口
    [ -n "$server_port" ] && port="$server_port" || port=51820
  fi
}

# 让用户输入自定义DNS服务器（交互式模式）
enter_custom_dns() {
  read -rp "请输入首选DNS服务器：" dns1
  # 验证首选DNS格式
  until check_ip "$dns1"; do
    echo "DNS服务器无效。"
    read -rp "请输入首选DNS服务器：" dns1
  done
  read -rp "请输入备用DNS服务器（按回车键跳过）：" dns2
  # 验证备用DNS格式（允许为空）
  until [ -z "$dns2" ] || check_ip "$dns2"; do
    echo "DNS服务器无效。"
    read -rp "请输入备用DNS服务器（按回车键跳过）：" dns2
  done
}

# 输入第一个客户端的名称（交互式或自动模式）
enter_first_client_name() {
  if [ "$auto" = 0 ]; then
    echo
    echo "请为第一个客户端输入名称："
    read -rp "名称 [client]：" unsanitized_client
    # 处理客户端名称（过滤特殊字符、限制长度）
    set_client_name
    # 若名称为空，使用默认名称client
    [[ -z "$client" ]] && client=client
  else
    # 自动模式下，使用自定义名称或默认名称
    if [ -n "$first_client_name" ]; then
      unsanitized_client="$first_client_name"
      set_client_name
    else
      client=client
    fi
  fi
}

# 提示用户配置已准备就绪（交互式模式）
show_setup_ready() {
  if [ "$auto" = 0 ]; then
    echo
    echo "WireGuard安装配置已准备就绪。"
  fi
}

# 检查防火墙状态（若无防火墙，自动安装对应的防火墙工具）
check_firewall() {
  # 若firewalld未运行且iptables未安装，需安装防火墙
  if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
    if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
      firewall="firewalld"
    elif [[ "$os" == "openSUSE" ]]; then
      firewall="firewalld"
    elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
      firewall="iptables"
    fi
    # 若需安装firewalld，提前提示用户
    if [[ "$firewall" == "firewalld" ]]; then
      echo
      echo "注意：将同时安装firewalld（用于管理路由表，WireGuard必需）。"
    fi
  fi
}

# 中止安装并退出（未修改系统配置）
abort_and_exit() {
  echo "已中止。未修改任何系统配置。" >&2
  exit 1
}

# 确认是否继续安装（交互式模式）
confirm_setup() {
  if [ "$auto" = 0 ]; then
    printf "是否继续安装？[Y/n] "
    read -r response
    case $response in
    [yY][eE][sS] | [yY] | '')
      # 继续安装
      :
      ;;
    *)
      # 中止安装
      abort_and_exit
      ;;
    esac
  fi
}

# 提示用户开始安装WireGuard
show_start_setup() {
  echo
  echo "正在安装WireGuard，请稍候..."
}

# 安装WireGuard及依赖包（根据操作系统选择包管理器）
install_pkgs() {
  if [[ "$os" == "ubuntu" ]]; then
    # Ubuntu：使用apt-get安装wireguard、qrencode和防火墙
    export DEBIAN_FRONTEND=noninteractive
    (
      set -x
      apt-get -yqq update || apt-get -yqq update
      apt-get -yqq install wireguard qrencode $firewall >/dev/null
    ) || exiterr2
  elif [[ "$os" == "debian" ]]; then
    # Debian：使用apt-get安装wireguard、qrencode和防火墙
    export DEBIAN_FRONTEND=noninteractive
    (
      set -x
      apt-get -yqq update || apt-get -yqq update
      apt-get -yqq install wireguard qrencode $firewall >/dev/null
    ) || exiterr2
  elif [[ "$os" == "centos" && "$os_version" -ge 9 ]]; then
    # CentOS 9+/AlmaLinux 9+/Rocky Linux 9+：使用yum安装
    (
      set -x
      yum -y -q install epel-release >/dev/null
      yum -y -q install wireguard-tools qrencode $firewall >/dev/null 2>&1
    ) || exiterr3
    # 创建WireGuard配置目录
    mkdir -p /etc/wireguard/
  elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
    # CentOS 8/AlmaLinux 8/Rocky Linux 8：需安装elrepo仓库获取wireguard内核模块
    (
      set -x
      yum -y -q install epel-release elrepo-release >/dev/null
      yum -y -q --nobest install kmod-wireguard >/dev/null 2>&1
      yum -y -q install wireguard-tools qrencode $firewall >/dev/null 2>&1
    ) || exiterr3
    # 创建WireGuard配置目录
    mkdir -p /etc/wireguard/
  elif [[ "$os" == "fedora" ]]; then
    # Fedora：使用dnf安装
    (
      set -x
      dnf install -y wireguard-tools qrencode $firewall >/dev/null
    ) || exiterr "'dnf install' 命令执行失败。"
    # 创建WireGuard配置目录
    mkdir -p /etc/wireguard/
  elif [[ "$os" == "openSUSE" ]]; then
    # openSUSE：使用zypper安装
    (
      set -x
      zypper install -y wireguard-tools qrencode $firewall >/dev/null
    ) || exiterr4
    # 创建WireGuard配置目录
    mkdir -p /etc/wireguard/
  fi
  # 检查WireGuard配置目录是否创建成功
  [ ! -d /etc/wireguard ] && exiterr2
  # 若刚安装了firewalld，启用并启动firewalld服务
  if [[ "$firewall" == "firewalld" ]]; then
    (
      set -x
      systemctl enable --now firewalld.service >/dev/null 2>&1
    )
  fi
}

# 卸载WireGuard及相关包（根据操作系统选择包管理器）
remove_pkgs() {
  if [[ "$os" == "ubuntu" ]]; then
    (
      set -x
      # 删除WireGuard配置目录
      rm -rf /etc/wireguard/
      # 彻底卸载wireguard相关包
      apt-get remove --purge -y wireguard wireguard-tools >/dev/null
    )
  elif [[ "$os" == "debian" ]]; then
    (
      set -x
      rm -rf /etc/wireguard/
      apt-get remove --purge -y wireguard wireguard-tools >/dev/null
    )
  elif [[ "$os" == "centos" && "$os_version" -ge 9 ]]; then
    (
      set -x
      yum -y -q remove wireguard-tools >/dev/null
      rm -rf /etc/wireguard/
    )
  elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
    (
      set -x
      # 卸载wireguard内核模块和工具
      yum -y -q remove kmod-wireguard wireguard-tools >/dev/null
      rm -rf /etc/wireguard/
    )
  elif [[ "$os" == "fedora" ]]; then
    (
      set -x
      dnf remove -y wireguard-tools >/dev/null
      rm -rf /etc/wireguard/
    )
  elif [[ "$os" == "openSUSE" ]]; then
    (
      set -x
      zypper remove -y wireguard-tools >/dev/null
      rm -rf /etc/wireguard/
    )
  fi
}

# 创建WireGuard服务器配置文件（/etc/wireguard/wg0.conf）
create_server_config() {
  # 生成服务器配置，包含接口信息（地址、私钥、监听端口）
  cat <<EOF >"$WG_CONF"
# 请勿修改以下注释行
# 这些注释行用于wireguard-install脚本识别配置
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
  # 设置配置文件权限（仅root可读写）
  chmod 600 "$WG_CONF"
}

# 创建防火墙规则（根据防火墙类型配置iptables或firewalld）
create_firewall_rules() {
  if systemctl is-active --quiet firewalld.service; then
    # 使用firewalld配置规则（临时+永久，避免重载firewalld）
    firewall-cmd -q --add-port="$port"/udp
    firewall-cmd -q --zone=trusted --add-source=10.7.0.0/24
    firewall-cmd -q --permanent --add-port="$port"/udp
    firewall-cmd -q --permanent --zone=trusted --add-source=10.7.0.0/24
    # 为VPN子网配置NAT转发（IPv4）
    firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
    firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
    # 若支持IPv6，配置IPv6防火墙规则
    if [[ -n "$ip6" ]]; then
      firewall-cmd -q --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
      firewall-cmd -q --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
      firewall-cmd -q --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
      firewall-cmd -q --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
    fi
  else
    # 使用iptables配置规则（创建系统服务确保规则持久化）
    iptables_path=$(command -v iptables)
    ip6tables_path=$(command -v ip6tables)
    # 若为OpenVZ环境且使用nftables后端，切换为iptables-legacy
    if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
      iptables_path=$(command -v iptables-legacy)
      ip6tables_path=$(command -v ip6tables-legacy)
    fi
    # 创建wg-iptables服务配置文件
    echo "[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
ExecStart=$iptables_path -w 5 -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
ExecStop=$iptables_path -w 5 -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >/etc/systemd/system/wg-iptables.service
    # 若支持IPv6，添加IPv6 iptables规则
    if [[ -n "$ip6" ]]; then
      echo "ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >>/etc/systemd/system/wg-iptables.service
    fi
    echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >>/etc/systemd/system/wg-iptables.service
    # 启用并启动wg-iptables服务
    (
      set -x
      systemctl enable --now wg-iptables.service >/dev/null 2>&1
    )
  fi
}

# 移除防火墙规则（卸载WireGuard时）
remove_firewall_rules() {
  # 从服务器配置中提取监听端口
  port=$(grep '^ListenPort' "$WG_CONF" | cut -d " " -f 3)
  if systemctl is-active --quiet firewalld.service; then
    # 移除firewalld规则（临时+永久）
    firewall-cmd -q --remove-port="$port"/udp
    firewall-cmd -q --zone=trusted --remove-source=10.7.0.0/24
    firewall-cmd -q --permanent --remove-port="$port"/udp
    firewall-cmd -q --permanent --zone=trusted --remove-source=10.7.0.0/24
    firewall-cmd -q --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
    firewall-cmd -q --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
    # 若配置了IPv6，移除IPv6规则
    if grep -qs 'fddd:2c4:2c4:2c4::1/64' "$WG_CONF"; then
      firewall-cmd -q --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
      firewall-cmd -q --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
      firewall-cmd -q --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
      firewall-cmd -q --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
    fi
  else
    # 停止并禁用wg-iptables服务，删除服务配置文件
    systemctl disable --now wg-iptables.service
    rm -f /etc/systemd/system/wg-iptables.service
  fi
}

# 确定客户端配置文件的导出目录（优先保存到sudo用户的家目录）
get_export_dir() {
  export_to_home_dir=0
  export_dir=~/
  # 若通过sudo执行脚本，且sudo用户存在，将配置保存到该用户家目录
  if [ -n "$SUDO_USER" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
    user_home_dir=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
    if [ -d "$user_home_dir" ] && [ "$user_home_dir" != "/" ]; then
      export_dir="$user_home_dir/"
      export_to_home_dir=1
    fi
  fi
}

# 选择客户端的DNS服务器（交互式模式）
select_dns() {
  if [ "$auto" = 0 ]; then
    echo
    echo "请为客户端选择DNS服务器："
    echo "   1) 系统当前使用的DNS服务器"
    echo "   2) 海外公共DNS=1.1.1.1"
    echo "   3) 阿里云 DNS"
    echo "   4) 自定义DNS服务器"
    read -rp "DNS服务器 [2]：" dns
    # 验证用户选择的合法性（空或1-7）
    until [[ -z "$dns" || "$dns" =~ ^[1-7]$ ]]; do
      echo "$dns：选择无效。"
      read -rp "DNS服务器 [2]：" dns
    done
  else
    # 自动模式下默认选择Google公共DNS
    dns=2
  fi
  # 根据选择配置DNS服务器
  case "$dns" in
  1)
    # 使用系统当前的DNS服务器
    # 处理systemd-resolved环境下的resolv.conf路径
    if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
      resolv_conf="/etc/resolv.conf"
    else
      resolv_conf="/run/systemd/resolve/resolv.conf"
    fi
    # 提取resolv.conf中的DNS服务器，格式化为"DNS1, DNS2"
    dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
    ;;
  2 | "")
    # 公共DNS（1.1.1.1）
    dns="1.1.1.1"
    ;;
  3)
    # Cloudflare DNS（1.1.1.1, 1.0.0.1）
    dns="223.5.5.5"
    ;;
  7)
    # 自定义DNS服务器（让用户输入）
    enter_custom_dns
    if [ -n "$dns2" ]; then
      dns="$dns1, $dns2"
    else
      dns="$dns1"
    fi
    ;;
  esac
}

# 为新客户端分配VPN子网内的IP地址（自动分配未使用的地址）
select_client_ip() {
  # 从10.7.0.2开始分配（10.7.0.1为服务器地址）
  octet=2
  # 循环查找第一个未被使用的IP地址（检查AllowedIPs字段）
  while grep AllowedIPs "$WG_CONF" | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
    ((octet++))
  done
  # 若IP地址段已满（超过254），报错退出
  if [[ "$octet" -eq 255 ]]; then
    exiterr "已配置253个客户端，WireGuard内部子网地址已用尽！"
  fi
}

# 创建新客户端的配置（服务器端+客户端）
new_client() {
  # 自动分配客户端IP地址
  select_client_ip
  specify_ip=n
  # 仅在交互式添加客户端时，允许用户手动指定IP
  if [ "$1" = "add_client" ] && [ "$add_client" = 0 ]; then
    echo
    read -rp "是否为新客户端手动指定内部IP地址？[y/N]：" specify_ip
    # 验证用户输入（y/Y/n/N）
    until [[ "$specify_ip" =~ ^[yYnN]*$ ]]; do
      echo "$specify_ip：选择无效。"
      read -rp "是否为新客户端手动指定内部IP地址？[y/N]：" specify_ip
    done
    if [[ ! "$specify_ip" =~ ^[yY]$ ]]; then
      echo "将自动为客户端分配IP地址：10.7.0.$octet。"
    fi
  fi
  # 若用户选择手动指定IP，验证IP格式和可用性
  if [[ "$specify_ip" =~ ^[yY]$ ]]; then
    echo
    read -rp "请输入新客户端的IP地址（例如10.7.0.X）：" client_ip
    octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
    # 验证IP是否在10.7.0.2-10.7.0.254范围内，且未被使用
    until [[ $client_ip =~ ^10\.7\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]] &&
      ! grep AllowedIPs "$WG_CONF" | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
      if [[ ! $client_ip =~ ^10\.7\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]]; then
        echo "IP地址无效。必须在10.7.0.2-10.7.0.254范围内。"
      else
        echo "该IP地址已被使用，请选择其他地址。"
      fi
      read -rp "请输入新客户端的IP地址（例如10.7.0.X）：" client_ip
      octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
    done
  fi
  # 生成客户端私钥和预共享密钥（PSK，增强安全性）
  key=$(wg genkey)
  psk=$(wg genpsk)
  # 在服务器配置中添加新客户端的Peer配置
  cat <<EOF >>"$WG_CONF"
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<<"$key")
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' "$WG_CONF" && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
  # 生成客户端配置文件（保存到用户家目录）
  get_export_dir
  cat <<EOF >"$export_dir$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' "$WG_CONF" && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey "$WG_CONF" | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' "$WG_CONF" | cut -d " " -f 3):$(grep ListenPort "$WG_CONF" | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
  # 若配置保存到sudo用户家目录，调整文件所有者
  if [ "$export_to_home_dir" = 1 ]; then
    chown "$SUDO_USER:$SUDO_USER" "$export_dir$client".conf
  fi
  # 设置客户端配置文件权限（仅所有者可读写）
  chmod 600 "$export_dir$client".conf
}

# 更新系统内核参数（启用IP转发、优化网络性能）
update_sysctl() {
  # 创建sysctl配置目录（若不存在）
  mkdir -p /etc/sysctl.d
  # 用于启用IP转发的配置文件
  conf_fwd="/etc/sysctl.d/99-wireguard-forward.conf"
  # 用于网络性能优化的配置文件
  conf_opt="/etc/sysctl.d/99-wireguard-optimize.conf"
  # 启用IPv4 IP转发（WireGuard必需）
  echo 'net.ipv4.ip_forward=1' >"$conf_fwd"
  # 若支持IPv6，启用IPv6转发
  if [[ -n "$ip6" ]]; then
    echo "net.ipv6.conf.all.forwarding=1" >>"$conf_fwd"
  fi
  # 从GitHub下载WireGuard网络优化配置（根据操作系统和安装模式）
  base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
  conf_url="$base_url/sysctl-wg-$os"
  [ "$auto" != 0 ] && conf_url="${conf_url}-auto"
  # 尝试用wget下载，失败则用curl，仍失败则创建空文件
  wget -t 3 -T 30 -q -O "$conf_opt" "$conf_url" 2>/dev/null ||
    curl -m 30 -fsL "$conf_url" -o "$conf_opt" 2>/dev/null ||
    {
      /bin/rm -f "$conf_opt"
      touch "$conf_opt"
    }
  # 若内核版本>=4.20，启用TCP BBR拥塞控制（提升网络性能）
  if modprobe -q tcp_bbr &&
    printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V &&
    [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
    cat >>"$conf_opt" <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
  fi
  # 应用sysctl配置（无需重启系统）
  sysctl -e -q -p "$conf_fwd"
  sysctl -e -q -p "$conf_opt"
}

# 更新/etc/rc.local（确保系统重启后重新加载iptables规则）
update_rclocal() {
  # 重启wg-iptables服务的命令
  ipt_cmd="systemctl restart wg-iptables.service"
  # 若rc.local中未包含该命令，添加到rc.local
  if ! grep -qs "$ipt_cmd" /etc/rc.local; then
    # 若rc.local不存在，创建该文件
    if [ ! -f /etc/rc.local ]; then
      echo '#!/bin/sh' >/etc/rc.local
    else
      # 移除Debian/Ubuntu系统rc.local中的exit 0（避免命令不执行）
      if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
        sed --follow-symlinks -i '/^exit 0/d' /etc/rc.local
      fi
    fi
    # 添加重启wg-iptables服务的命令
    cat >>/etc/rc.local <<EOF

$ipt_cmd
EOF
    # 在Debian/Ubuntu系统rc.local末尾添加exit 0
    if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
      echo "exit 0" >>/etc/rc.local
    fi
    # 设置rc.local为可执行
    chmod +x /etc/rc.local
  fi
}

# 启用并启动WireGuard服务（wg-quick@wg0）
start_wg_service() {
  (
    set -x
    systemctl enable --now wg-quick@wg0.service >/dev/null 2>&1
  )
}

# 显示客户端配置的QR码（用于手机客户端扫码导入）
show_client_qr_code() {
  qrencode -t UTF8 <"$export_dir$client".conf
  echo -e '\xE2\x86\x91 以上为客户端配置的QR码，手机客户端可扫码导入。'
}

# 安装完成后显示总结信息
finish_setup() {
  echo
  # 检查WireGuard内核模块是否加载成功（旧内核可能失败）
  if ! modprobe -nq wireguard; then
    echo "警告！"
    echo "安装已完成，但WireGuard内核模块未能加载。"
    echo "请重启系统以加载最新内核。"
  else
    echo "安装完成！"
  fi
  echo
  echo "客户端配置文件已保存至：$export_dir$client.conf"
  echo "如需添加新客户端，重新运行此脚本即可。"
}

# 显示已安装WireGuard后的操作菜单（交互式模式）
# 显示已安装WireGuard后的操作菜单（交互式模式）
select_menu_option() {
  echo
  echo "WireGuard已安装完成。"
  echo
  echo "请选择操作："
  echo "   1) 添加新客户端"
  echo "   2) 列出所有已存在的客户端"
  echo "   3) 删除指定客户端"
  echo "   4) 显示指定客户端的QR码"
  echo "   5) 卸载WireGuard"
  echo "   6) 退出"
  read -rp "选择操作 [1-6]：" option
  # 验证用户输入的合法性（必须是1-6的整数）
  until [[ "$option" =~ ^[1-6]$ ]]; do
    echo "$option：选择无效。"
    read -rp "选择操作 [1-6]：" option
  done
}

# 列出所有已存在的客户端（从服务器配置中提取）
show_clients() {
  grep '^# BEGIN_PEER' "$WG_CONF" | cut -d ' ' -f 3 | nl -s ') '
}

# 让用户输入新客户端的名称（交互式添加客户端时）
enter_client_name() {
  echo
  echo "请为新客户端输入名称："
  read -rp "名称：" unsanitized_client
  # 若用户未输入名称，中止操作
  [ -z "$unsanitized_client" ] && abort_and_exit
  # 处理客户端名称（过滤特殊字符、限制长度）
  set_client_name
  # 验证名称合法性（非空且未重复）
  while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; do
    if [ -z "$client" ]; then
      echo "客户端名称无效。仅可使用单个单词，特殊字符仅支持 '-' 和 '_'。"
    else
      echo "$client：名称已存在，请重新输入。"
    fi
    read -rp "名称：" unsanitized_client
    [ -z "$unsanitized_client" ] && abort_and_exit
    set_client_name
  done
}

# 将新客户端配置更新到运行中的WireGuard接口（无需重启服务）
update_wg_conf() {
  # 提取新客户端的Peer配置并添加到wg0接口
  wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" "$WG_CONF")
}

# 显示客户端添加成功的提示信息
print_client_added() {
  echo
  echo "$client 添加成功。配置文件已保存至：$export_dir$client.conf"
}

# 显示“正在检查客户端”的提示信息
print_check_clients() {
  echo
  echo "正在检查已存在的客户端..."
}

# 检查是否存在已配置的客户端（无客户端时报错退出）
check_clients() {
  num_of_clients=$(grep -c '^# BEGIN_PEER' "$WG_CONF")
  if [[ "$num_of_clients" = 0 ]]; then
    echo
    echo "当前无已配置的客户端！"
    exit 1
  fi
}

# 显示客户端总数
print_client_total() {
  if [ "$num_of_clients" = 1 ]; then
    printf '\n%s\n' "总计：1个客户端"
  elif [ -n "$num_of_clients" ]; then
    printf '\n%s\n' "总计：$num_of_clients个客户端"
  fi
}

# 让用户选择要执行操作（删除/显示QR码）的客户端
select_client_to() {
  echo
  echo "请选择要$1的客户端："
  show_clients
  read -rp "客户端编号：" client_num
  # 若用户未输入编号，中止操作
  [ -z "$client_num" ] && abort_and_exit
  # 验证编号合法性（必须是1到客户端总数之间的整数）
  until [[ "$client_num" =~ ^[0-9]+$ && "$client_num" -le "$num_of_clients" ]]; do
    echo "$client_num：选择无效。"
    read -rp "客户端编号：" client_num
    [ -z "$client_num" ] && abort_and_exit
  done
  # 根据编号提取对应的客户端名称
  client=$(grep '^# BEGIN_PEER' "$WG_CONF" | cut -d ' ' -f 3 | sed -n "$client_num"p)
}

# 确认是否删除指定客户端（交互式模式，--yes参数可跳过）
confirm_remove_client() {
  if [ "$assume_yes" != 1 ]; then
    echo
    read -rp "确认删除 $client 吗？[y/N]：" remove
    # 验证用户输入（仅接受y/Y/n/N）
    until [[ "$remove" =~ ^[yYnN]*$ ]]; do
      echo "$remove：选择无效。"
      read -rp "确认删除 $client 吗？[y/N]：" remove
    done
  else
    # --yes参数已指定，默认确认删除
    remove=y
  fi
}

# 删除客户端的配置文件（若存在）
remove_client_conf() {
  get_export_dir
  wg_file="$export_dir$client.conf"
  if [ -f "$wg_file" ]; then
    echo "正在删除客户端配置文件：$wg_file..."
    rm -f "$wg_file"
  fi
}

# 显示“正在删除客户端”的提示信息
print_remove_client() {
  echo
  echo "正在删除客户端 $client..."
}

# 从WireGuard中删除指定客户端（实时生效+删除配置）
remove_client_wg() {
  # 正确的删除方式（不影响其他客户端连接）：
  # 1. 从运行中的wg0接口移除客户端
  wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" "$WG_CONF" | grep -m 1 PublicKey | cut -d " " -f 3)" remove
  # 2. 从服务器配置文件中删除客户端的Peer配置
  sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" "$WG_CONF"
  # 3. 删除客户端的本地配置文件
  remove_client_conf
}

# 显示客户端删除成功的提示信息
print_client_removed() {
  echo
  echo "$client 删除成功！"
}

# 显示客户端删除中止的提示信息
print_client_removal_aborted() {
  echo
  echo "$client 删除操作已中止！"
}

# 检查客户端配置文件是否存在（显示QR码前必需）
check_client_conf() {
  wg_file="$export_dir$client.conf"
  if [ ! -f "$wg_file" ]; then
    echo "错误：无法显示QR码，客户端配置文件 $wg_file 不存在。" >&2
    echo "       您可以重新运行此脚本并添加新客户端。" >&2
    exit 1
  fi
}

# 显示客户端配置文件的路径
print_client_conf() {
  echo
  echo "'$client' 的配置文件路径：$wg_file"
}

# 确认是否卸载WireGuard（交互式模式，--yes参数可跳过）
confirm_remove_wg() {
  if [ "$assume_yes" != 1 ]; then
    echo
    read -rp "确认卸载WireGuard吗？[y/N]：" remove
    # 验证用户输入（仅接受y/Y/n/N）
    until [[ "$remove" =~ ^[yYnN]*$ ]]; do
      echo "$remove：选择无效。"
      read -rp "确认卸载WireGuard吗？[y/N]：" remove
    done
  else
    # --yes参数已指定，默认确认卸载
    remove=y
  fi
}

# 显示“正在卸载WireGuard”的提示信息
print_remove_wg() {
  echo
  echo "正在卸载WireGuard，请稍候..."
}

# 禁用并停止WireGuard服务
disable_wg_service() {
  systemctl disable --now wg-quick@wg0.service
}

# 移除WireGuard相关的sysctl配置（恢复默认内核参数）
remove_sysctl_rules() {
  rm -f /etc/sysctl.d/99-wireguard-forward.conf /etc/sysctl.d/99-wireguard-optimize.conf
  # 若系统未安装其他VPN（OpenVPN/IPsec），关闭IP转发
  if [ ! -f /usr/sbin/openvpn ] && [ ! -f /usr/sbin/ipsec ] &&
    [ ! -f /usr/local/sbin/ipsec ]; then
    echo 0 >/proc/sys/net/ipv4/ip_forward
    echo 0 >/proc/sys/net/ipv6/conf/all/forwarding
  fi
}

# 从rc.local中移除WireGuard相关的规则
remove_rclocal_rules() {
  ipt_cmd="systemctl restart wg-iptables.service"
  if grep -qs "$ipt_cmd" /etc/rc.local; then
    sed --follow-symlinks -i "/^$ipt_cmd/d" /etc/rc.local
  fi
}

# 显示WireGuard卸载成功的提示信息
print_wg_removed() {
  echo
  echo "WireGuard卸载成功！"
}

# 显示WireGuard卸载中止的提示信息
print_wg_removal_aborted() {
  echo
  echo "WireGuard卸载操作已中止！"
}

# WireGuard核心配置函数（整合所有步骤）
wgsetup() {

  # 设置环境变量PATH（确保命令可正常找到）
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

  # 前置检查：root权限、shell类型、内核版本、操作系统、操作系统版本、是否为容器
  check_root
  check_shell
  check_kernel
  check_os
  check_os_ver
  check_container

  # WireGuard服务器配置文件路径
  WG_CONF="/etc/wireguard/wg0.conf"

  # 初始化变量（默认值）
  auto=0                # 是否自动安装模式
  assume_yes=0          # 是否默认确认（--yes参数）
  add_client=0          # 是否执行添加客户端操作
  list_clients=0        # 是否执行列出客户端操作
  remove_client=0       # 是否执行删除客户端操作
  show_client_qr=0      # 是否执行显示客户端QR码操作
  remove_wg=0           # 是否执行卸载WireGuard操作
  public_ip=""          # 服务器公网IP（仅NAT环境需要）
  server_addr=""        # 自动安装时指定的服务器地址（FQDN/IP）
  server_port=""        # 自动安装时指定的监听端口
  first_client_name=""  # 自动安装时指定的第一个客户端名称
  unsanitized_client="" # 未处理的客户端名称（用户输入）
  client=""             # 处理后的客户端名称（过滤特殊字符）
  dns=""                # 客户端DNS服务器配置字符串
  dns1=""               # 客户端首选DNS服务器（--dns1参数）
  dns2=""               # 客户端备用DNS服务器（--dns2参数）

  # 解析命令行参数
  parse_args "$@"
  # 检查参数合法性
  check_args

  # 分支1：执行添加客户端操作
  if [ "$add_client" = 1 ]; then
    show_header
    new_client add_client
    update_wg_conf
    echo
    show_client_qr_code
    print_client_added
    exit 0
  fi

  # 分支2：执行列出客户端操作
  if [ "$list_clients" = 1 ]; then
    show_header
    print_check_clients
    check_clients
    echo
    show_clients
    print_client_total
    exit 0
  fi

  # 分支3：执行删除客户端操作
  if [ "$remove_client" = 1 ]; then
    show_header
    confirm_remove_client
    if [[ "$remove" =~ ^[yY]$ ]]; then
      print_remove_client
      remove_client_wg
      print_client_removed
      exit 0
    else
      print_client_removal_aborted
      exit 1
    fi
  fi

  # 分支4：执行显示客户端QR码操作
  if [ "$show_client_qr" = 1 ]; then
    show_header
    echo
    get_export_dir
    check_client_conf
    show_client_qr_code
    print_client_conf
    exit 0
  fi

  # 分支5：执行卸载WireGuard操作
  if [ "$remove_wg" = 1 ]; then
    show_header
    confirm_remove_wg
    if [[ "$remove" =~ ^[yY]$ ]]; then
      print_remove_wg
      remove_firewall_rules
      disable_wg_service
      remove_sysctl_rules
      remove_rclocal_rules
      remove_pkgs
      print_wg_removed
      exit 0
    else
      print_wg_removal_aborted
      exit 1
    fi
  fi

  # 分支6：首次安装WireGuard（未存在配置文件）
  if [[ ! -e "$WG_CONF" ]]; then
    # 额外检查：CentOS系统是否启用nftables（不支持）
    check_nftables
    # 安装必需工具：wget、iproute2
    install_wget
    install_iproute
    # 显示欢迎信息
    show_welcome
    # 处理服务器地址（自动模式vs交互式模式）
    if [ "$auto" = 0 ]; then
      enter_server_address
    else
      if [ -n "$server_addr" ]; then
        ip="$server_addr"
      else
        detect_ip
        check_nat_ip
      fi
    fi
    # 显示配置信息（仅自动模式）
    show_config
    # 检测IPv6支持
    detect_ipv6
    # 选择监听端口
    select_port
    # 输入第一个客户端名称
    enter_first_client_name
    # 选择DNS服务器（仅交互式模式）
    if [ "$auto" = 0 ]; then
      select_dns
    fi
    # 提示配置就绪
    show_setup_ready
    # 检查防火墙（无防火墙则自动安装）
    check_firewall
    # 确认是否继续安装
    confirm_setup
    # 提示开始安装
    show_start_setup
    # 安装WireGuard及依赖包
    install_pkgs
    # 创建服务器配置文件
    create_server_config
    # 更新sysctl内核参数（启用转发、优化网络）
    update_sysctl
    # 创建防火墙规则
    create_firewall_rules
    # 非openSUSE系统：更新rc.local（确保重启后加载iptables规则）
    if [ "$os" != "openSUSE" ]; then
      update_rclocal
    fi
    # 创建第一个客户端配置
    new_client
    # 启用并启动WireGuard服务
    start_wg_service
    echo
    # 显示第一个客户端的QR码
    show_client_qr_code
    # 若自动模式且使用DNS名称，显示解析提醒
    if [ "$auto" != 0 ] && check_dns_name "$server_addr"; then
      show_dns_name_note "$server_addr"
    fi
    # 显示安装完成信息
    finish_setup
  # 分支7：已安装WireGuard（存在配置文件），显示操作菜单
  else
    show_header
    # 显示操作菜单并获取用户选择
    select_menu_option
    case "$option" in
    1)
      # 选项1：添加新客户端
      enter_client_name
      select_dns
      new_client add_client
      update_wg_conf
      echo
      show_client_qr_code
      print_client_added
      exit 0
      ;;
    2)
      # 选项2：列出所有客户端
      print_check_clients
      check_clients
      echo
      show_clients
      print_client_total
      exit 0
      ;;
    3)
      # 选项3：删除指定客户端
      check_clients
      select_client_to "删除"
      confirm_remove_client
      if [[ "$remove" =~ ^[yY]$ ]]; then
        print_remove_client
        remove_client_wg
        print_client_removed
        exit 0
      else
        print_client_removal_aborted
        exit 1
      fi
      ;;
    4)
      # 选项4：显示指定客户端的QR码
      check_clients
      select_client_to "显示QR码"
      echo
      get_export_dir
      check_client_conf
      show_client_qr_code
      print_client_conf
      exit 0
      ;;
    5)
      # 选项5：卸载WireGuard
      confirm_remove_wg
      if [[ "$remove" =~ ^[yY]$ ]]; then
        print_remove_wg
        remove_firewall_rules
        disable_wg_service
        remove_sysctl_rules
        remove_rclocal_rules
        remove_pkgs
        print_wg_removed
        exit 0
      else
        print_wg_removal_aborted
        exit 1
      fi
      ;;
    6)
      # 选项6：退出脚本
      exit 0
      ;;
    esac
  fi
}

## 延迟执行核心配置函数（确保脚本完全加载后再运行）
wgsetup "$@"

exit 0
