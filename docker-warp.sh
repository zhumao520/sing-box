#!/bin/bash

# 检查WARP SOCKS代理是否正常运行
check_warp_socks_proxy() {
    echo "正在检查WARP SOCKS代理(127.0.0.1:1080)连通性..."
    
    # 等待WARP容器启动
    sleep 3
    
    # 使用curl通过SOCKS代理获取IP，测试代理是否工作
    if command -v curl &> /dev/null; then
        echo "使用curl测试SOCKS代理..."
        if curl --connect-timeout 10 --max-time 15 -s --socks5 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace | grep -q "warp=on"; then
            echo "$(tput setaf 2)✓ WARP SOCKS代理运行正常，已连接到Cloudflare WARP网络$(tput sgr0)"
            
            # 显示WARP IP信息
            local warp_ip=$(curl -s --socks5 127.0.0.1:1080 https://api.ipify.org)
            echo "$(tput setaf 6)WARP代理IP地址: $warp_ip$(tput sgr0)"
            
            # 显示WARP IP地理位置
            local warp_ip_info=$(curl -s "http://ip-api.com/json/${warp_ip}")
            local country=$(echo "$warp_ip_info" | jq -r '.country // "Unknown"')
            local city=$(echo "$warp_ip_info" | jq -r '.city // "Unknown"')
            local isp=$(echo "$warp_ip_info" | jq -r '.isp // "Unknown"')
            echo "$(tput setaf 6)WARP IP位置: $country, $city ($isp)$(tput sgr0)"
        else
            echo "$(tput setaf 1)✗ WARP SOCKS代理测试失败$(tput sgr0)"
            
            # 检查Docker日志
            echo "检查WARP容器日志..."
            docker logs --tail 20 warp
            
            # 检查容器状态
            echo "检查WARP容器状态..."
            docker ps -a | grep warp
            
            echo "$(tput setaf 3)提示：可能需要多等待一会儿，WARP连接初始化可能需要一些时间$(tput sgr0)"
            echo "$(tput setaf 3)如果长时间无法连接，可以尝试重启WARP容器: docker restart warp$(tput sgr0)"
        fi
    else
        echo "未安装curl，无法测试SOCKS代理连通性"
    fi
    
    # 测试TCP连通性
    echo "测试TCP连通性..."
    if command -v nc &> /dev/null; then
        if nc -z -w5 127.0.0.1 1080; then
            echo "$(tput setaf 2)✓ TCP端口1080可访问$(tput sgr0)"
        else
            echo "$(tput setaf 1)✗ TCP端口1080不可访问$(tput sgr0)"
        fi
    else
        if command -v telnet &> /dev/null; then
            echo "使用telnet测试端口..."
            timeout 5 telnet 127.0.0.1 1080 > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "$(tput setaf 2)✓ TCP端口1080可访问$(tput sgr0)"
            else
                echo "$(tput setaf 1)✗ TCP端口1080不可访问$(tput sgr0)"
            fi
        else
            echo "未安装nc或telnet，无法测试TCP连通性"
        fi
    fi
}

# 命令行参数处理
case "$1" in
    check)
        # 直接检查WARP代理状态
        check_warp_socks_proxy
        exit 0
        ;;
    uninstall)
        # 卸载功能
        uninstall_warp
        exit 0
        ;;
esac

# 检查并安装必需的工具
check_and_install_tools() {
    local tools=("wget" "jq" "expect" "curl")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool 未安装，正在安装..."
            sudo apt-get update && sudo apt-get install -y "$tool"
        else
            echo "$tool 已安装"
        fi
    done
}

# 获取外网IP地址
get_external_ip() {
    curl -s http://ip.sb
}

# 获取IP地址的信息
get_ip_info() {
    local ip="$1"
    local response=$(curl -s "http://ip-api.com/json/${ip}?lang=zh-CN")
    local country=$(echo "$response" | jq -r '.country // "Unknown"')
    local query=$(echo "$response" | jq -r '.query // "Unknown"')
    local city=$(echo "$response" | jq -r '.city // "Unknown"')
    local org=$(echo "$response" | jq -r '.org // "Unknown"')

    echo "$country,$query,$city,$org"
}

# 检查 singbox 是否已安装
check_and_install_singbox() {
    if ! command -v sing-box &> /dev/null; then
        echo "sing-box 未安装，正在安装..."
        bash <(wget -qO- https://github.com/zhumao520/sing-box/raw/main/install.sh)
    else
        echo "sing-box 已安装"
        check_hysteria2_files
    fi
}

# 检查是否存在 Hysteria2 配置文件
check_hysteria2_files() {
    local config_dir="/etc/sing-box/conf"
    local files=("$config_dir"/Hysteria2-*.json)
    if [ -e "${files[0]}" ]; then
        echo "Hysteria2 配置文件已存在"
    else
        echo "Hysteria2 配置文件不存在，正在重新安装 sing-box..."
        local output=$(bash <(wget -qO- https://github.com/zhumao520/sing-box/raw/main/install.sh))
        echo "$output"
        if ! echo "$output" | grep -q "Hysteria2"; then
            echo "没有检测到 Hysteria2 字符，请手动运行 sb 进行配置。"
            sb
            echo "请在 sb 配置完成后按 Enter 继续..."
            read -r
        fi
    fi
}

# 检查是否安装Docker
check_docker_installed() {
    if ! command -v docker &> /dev/null; then
        return 1
    else
        return 0
    fi
}

# 安装Docker
install_docker() {
    sudo apt-get update
    sudo apt-get install -y docker.io
    sudo systemctl start docker
    sudo systemctl enable docker
}

# 检查是否存在名为warp的容器
check_warp_container() {
    if [ "$(docker ps -a --format '{{.Names}}' | grep -w "warp" | wc -l)" -eq 0 ]; then
        return 1
    else
        return 0
    fi
}

# 创建Warp容器所需的目录并运行容器
install_warp_container() {
    mkdir -p /mnt/warp/data && \
    docker run -d --name warp --restart always -p 127.0.0.1:1080:1080 \
    -e WARP_SLEEP=2 -e WARP_LICENSE_KEY=94A3DxI1-1od769nM-Z5D9bx81 \
    --cap-add=NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv4.conf.all.src_valid_mark=1 \
    -v /mnt/warp/data:/var/lib/cloudflare-warp \
    caomingjun/warp
}

# 修改Hysteria2配置文件并生成链接
modify_hysteria2_config() {
    local config_dir="/etc/sing-box/conf"
    for file in "$config_dir"/*.json; do
        if [ -f "$file" ];then
            local filename=$(basename "$file")
            
            # 根据不同协议类型读取不同的配置参数
            if [[ "$filename" == Hysteria2-* ]]; then
                local password=$(jq -r '.inbounds[0].users[0].password' "$file")
                local listen_port=$(jq -r '.inbounds[0].listen_port' "$file")
                local socks_tag="socks-out-${filename}"
                
                cat <<EOF > "$file"
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "tag": "$filename",
      "type": "hysteria2",
      "listen": "::",
      "listen_port": $listen_port,
      "users": [
        {
          "password": "$password"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "key_path": "/etc/sing-box/bin/tls.key",
        "certificate_path": "/etc/sing-box/bin/tls.cer"
      }
    }
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "$socks_tag",
      "server": "127.0.0.1",
      "server_port": 1080
    },
    {
      "type": "direct",
      "tag": "direct-out-${filename}"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": [
          "$filename"
        ],
        "outbound": "$socks_tag"
      }
    ],
    "final": "direct-out-${filename}"
  }
}
EOF

                local ip_address=$(get_external_ip)
                local ip_info=$(get_ip_info "$ip_address")
                local country=$(echo "$ip_info" | cut -d',' -f1)
                local query=$(echo "$ip_info" | cut -d',' -f2)
                local city=$(echo "$ip_info" | cut -d',' -f3)
                local org=$(echo "$ip_info" | cut -d',' -f4)

                # 处理可能的 null 值
                country=${country:-"Unknown"}
                query=${region:-"Unknown"}
                city=${city:-"Unknown"}
                org=${org:-"Unknown"}

                local hysteria2_link="hysteria2://${password}@${ip_address}:${listen_port}?alpn=h3&insecure=1#${country}-${ip_address}-${city}-${org}-WARP"
                echo "生成的Hysteria2链接：$(tput setaf 4)$hysteria2_link$(tput sgr0)"
            elif [[ "$filename" == VLESS-* ]]; then
                local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$file" 2>/dev/null)
                local listen_port=$(jq -r '.inbounds[0].listen_port' "$file" 2>/dev/null)
                local transport_type=$(jq -r '.inbounds[0].transport.type' "$file" 2>/dev/null || echo "")
                local server_name=$(jq -r '.inbounds[0].tls.server_name' "$file" 2>/dev/null || echo "")
                local private_key=$(jq -r '.inbounds[0].tls.reality.private_key' "$file" 2>/dev/null || echo "")
                local path=$(jq -r '.inbounds[0].transport.path' "$file" 2>/dev/null || echo "")
                local socks_tag="socks-out-${filename}"
                
                # 保留VLESS协议的原始入站配置
                local inbounds_config=$(jq '.inbounds[0]' "$file")
                
                cat <<EOF > "$file"
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    $inbounds_config
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "$socks_tag",
      "server": "127.0.0.1",
      "server_port": 1080
    },
    {
      "type": "direct",
      "tag": "direct-out-${filename}"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": [
          "$filename"
        ],
        "outbound": "$socks_tag"
      }
    ],
    "final": "direct-out-${filename}"
  }
}
EOF
                echo "VLESS配置文件 $filename 已更新，出站流量经过WARP"
            elif [[ "$filename" == Trojan-* ]]; then
                local password=$(jq -r '.inbounds[0].users[0].password' "$file" 2>/dev/null)
                local listen_port=$(jq -r '.inbounds[0].listen_port' "$file" 2>/dev/null)
                local socks_tag="socks-out-${filename}"
                
                # 保留Trojan协议的原始入站配置
                local inbounds_config=$(jq '.inbounds[0]' "$file")
                
                cat <<EOF > "$file"
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    $inbounds_config
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "$socks_tag",
      "server": "127.0.0.1",
      "server_port": 1080
    },
    {
      "type": "direct",
      "tag": "direct-out-${filename}"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": [
          "$filename"
        ],
        "outbound": "$socks_tag"
      }
    ],
    "final": "direct-out-${filename}"
  }
}
EOF
                echo "Trojan配置文件 $filename 已更新，出站流量经过WARP"
            elif [[ "$filename" == TUIC-* ]]; then
                # 保留TUIC协议的原始入站配置
                local inbounds_config=$(jq '.inbounds[0]' "$file")
                local socks_tag="socks-out-${filename}"
                
                cat <<EOF > "$file"
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    $inbounds_config
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "$socks_tag",
      "server": "127.0.0.1",
      "server_port": 1080
    },
    {
      "type": "direct",
      "tag": "direct-out-${filename}"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": [
          "$filename"
        ],
        "outbound": "$socks_tag"
      }
    ],
    "final": "direct-out-${filename}"
  }
}
EOF
                echo "TUIC配置文件 $filename 已更新，出站流量经过WARP"
            elif [[ "$filename" == VMess-* ]]; then
                # 保留VMess协议的原始入站配置
                local inbounds_config=$(jq '.inbounds[0]' "$file")
                local socks_tag="socks-out-${filename}"
                
                cat <<EOF > "$file"
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    $inbounds_config
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "$socks_tag",
      "server": "127.0.0.1",
      "server_port": 1080
    },
    {
      "type": "direct",
      "tag": "direct-out-${filename}"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": [
          "$filename"
        ],
        "outbound": "$socks_tag"
      }
    ],
    "final": "direct-out-${filename}"
  }
}
EOF
                echo "VMess配置文件 $filename 已更新，出站流量经过WARP"
            elif [[ "$filename" == Shadowsocks-* ]]; then
                # 保留Shadowsocks协议的原始入站配置
                local inbounds_config=$(jq '.inbounds[0]' "$file")
                local socks_tag="socks-out-${filename}"
                
                cat <<EOF > "$file"
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    $inbounds_config
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "$socks_tag",
      "server": "127.0.0.1",
      "server_port": 1080
    },
    {
      "type": "direct",
      "tag": "direct-out-${filename}"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": [
          "$filename"
        ],
        "outbound": "$socks_tag"
      }
    ],
    "final": "direct-out-${filename}"
  }
}
EOF
                echo "Shadowsocks配置文件 $filename 已更新，出站流量经过WARP"
            else
                echo "跳过不支持的配置文件: $filename"
            fi
        fi
    done
}

# 手动生成链接
generate_subscription() {
    echo -e "\n$(tput setaf 2)正在生成所有协议的链接...$(tput sgr0)"
    local config_dir="/etc/sing-box/conf"
    
    # 获取IP信息
    local ip_address=$(get_external_ip)
    local ip_info=$(get_ip_info "$ip_address")
    local country=$(echo "$ip_info" | cut -d',' -f1)
    local query=$(echo "$ip_info" | cut -d',' -f2)
    local city=$(echo "$ip_info" | cut -d',' -f3)
    local org=$(echo "$ip_info" | cut -d',' -f4)
    
    # 处理可能的 null 值
    country=${country:-"Unknown"}
    query=${query:-"Unknown"}
    city=${city:-"Unknown"}
    org=${org:-"Unknown"}
    
    # 获取CPU架构信息
    local cpu_arch=$(uname -m)
    if [[ "$cpu_arch" == "x86_64" ]]; then
        cpu_type="AMD64"
    elif [[ "$cpu_arch" == "aarch64" ]]; then
        cpu_type="ARM64"
    else
        cpu_type=$cpu_arch
    fi
    
    # 直接打印所有配置文件的链接
    for file in "$config_dir"/*.json; do
        if [ -f "$file" ]; then
            local filename=$(basename "$file")
            
            # 对于VLESS-REALITY类型，先修正配置文件中的pbk参数
            if [[ "$filename" == VLESS-REALITY-* ]]; then
                # 检查是否存在错误的pbk参数
                local pbk_check=$(jq -r '.inbounds[0].tls.reality.private_key' "$file" 2>/dev/null || echo "")
                # 如果pbk参数以"direct-out-"开头，说明可能有错误
                if [[ "$pbk_check" == *"direct-out-"* ]]; then
                    # 提取公钥 (假设我们有公钥，否则生成一个)
                    local correct_pbk="Sft3NCiChrqj7aI5ZJx8GrsApALWY2Up0vwHl6jqWWc"
                    # 更新配置文件的pbk
                    jq --arg pbk "$correct_pbk" '.inbounds[0].tls.reality.private_key = $pbk' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
                    echo "已修复 $filename 中的 pbk 参数"
                fi
            fi
            
            # 使用sing-box的url命令获取链接
            echo "正在处理 $filename..."
            # 使用自带工具生成URL
            local sb_url_output=$(cd /etc/sing-box && sb url $filename 2>&1)
            if [[ $sb_url_output == *"警告"* || $sb_url_output == *"错误"* ]]; then
                echo "$(tput setaf 3)${filename}:$(tput sgr0) $(tput setaf 1)生成链接失败，请检查配置$(tput sgr0)"
                echo "$sb_url_output" | grep -v "警告"
            else
                # 提取URL部分
                local link=$(echo "$sb_url_output" | grep -Eo '(vless|hysteria2|vmess|trojan|tuic)://[^ ]+' | head -1)
                if [[ -n "$link" ]]; then
                    echo "$(tput setaf 3)${filename}:$(tput sgr0) $(tput setaf 4)$link$(tput sgr0)"
                else
                    echo "$(tput setaf 3)${filename}:$(tput sgr0) $(tput setaf 1)无法提取链接$(tput sgr0)"
                fi
            fi
        fi
    done
    
    # 手动生成链接
    echo -e "\n$(tput setaf 2)手动生成的链接:$(tput sgr0)"
    for file in "$config_dir"/*.json; do
        if [ -f "$file" ]; then
            local filename=$(basename "$file")
            local protocol=$(echo "$filename" | cut -d'-' -f1)
            
            if [[ "$protocol" == "Hysteria2" ]]; then
                local password=$(jq -r '.inbounds[0].users[0].password' "$file" 2>/dev/null || echo "")
                local listen_port=$(jq -r '.inbounds[0].listen_port' "$file" 2>/dev/null || echo "")
                
                if [[ -n "$password" && -n "$listen_port" && -n "$ip_address" ]]; then
                    # 创建详细的备注信息
                    local remark="${country}-${ip_address}-${city}-${org}-${cpu_type}-WARP"
                    local hysteria2_link="hysteria2://${password}@${ip_address}:${listen_port}?alpn=h3&insecure=1#${remark}"
                    echo "$(tput setaf 3)${filename} (手动):$(tput sgr0) $(tput setaf 4)$hysteria2_link$(tput sgr0)"
                fi
            elif [[ "$protocol" == "VLESS" && "$filename" == *"REALITY"* ]]; then
                local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$file" 2>/dev/null || echo "")
                local listen_port=$(jq -r '.inbounds[0].listen_port' "$file" 2>/dev/null || echo "")
                local server_name=$(jq -r '.inbounds[0].tls.server_name' "$file" 2>/dev/null || echo "aws.amazon.com")
                local pbk=$(jq -r '.inbounds[0].tls.reality.public_key // .inbounds[0].tls.reality.private_key' "$file" 2>/dev/null || echo "")
                
                if [[ -n "$uuid" && -n "$listen_port" && -n "$ip_address" ]]; then
                    # 创建详细的备注信息
                    local remark="${country}-${ip_address}-${city}-${org}-${cpu_type}-WARP"
                    local vless_link="vless://${uuid}@${ip_address}:${listen_port}?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=${server_name}&fp=chrome#${remark}"
                    echo "$(tput setaf 3)${filename} (手动):$(tput sgr0) $(tput setaf 4)$vless_link$(tput sgr0)"
                fi
            fi
        fi
    done
    
    # Base64编码所有链接（可选，用于订阅）
    echo -e "\n$(tput setaf 2)如需订阅链接，请复制以下Base64编码:$(tput sgr0)"
    local temp_file=$(mktemp)
    
    # 手动生成链接并写入临时文件
    for file in "$config_dir"/*.json; do
        if [ -f "$file" ]; then
            local filename=$(basename "$file")
            local protocol=$(echo "$filename" | cut -d'-' -f1)
            
            if [[ "$protocol" == "Hysteria2" ]]; then
                local password=$(jq -r '.inbounds[0].users[0].password' "$file" 2>/dev/null || echo "")
                local listen_port=$(jq -r '.inbounds[0].listen_port' "$file" 2>/dev/null || echo "")
                
                if [[ -n "$password" && -n "$listen_port" && -n "$ip_address" ]]; then
                    # 创建详细的备注信息
                    local remark="${country}-${ip_address}-${city}-${org}-${cpu_type}-WARP"
                    local hysteria2_link="hysteria2://${password}@${ip_address}:${listen_port}?alpn=h3&insecure=1#${remark}"
                    echo "$hysteria2_link" >> "$temp_file"
                fi
            elif [[ "$protocol" == "VLESS" && "$filename" == *"REALITY"* ]]; then
                local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$file" 2>/dev/null || echo "")
                local listen_port=$(jq -r '.inbounds[0].listen_port' "$file" 2>/dev/null || echo "")
                local server_name=$(jq -r '.inbounds[0].tls.server_name' "$file" 2>/dev/null || echo "aws.amazon.com")
                local pbk=$(jq -r '.inbounds[0].tls.reality.public_key // .inbounds[0].tls.reality.private_key' "$file" 2>/dev/null || echo "")
                
                if [[ -n "$uuid" && -n "$listen_port" && -n "$ip_address" ]]; then
                    # 创建详细的备注信息
                    local remark="${country}-${ip_address}-${city}-${org}-${cpu_type}-WARP"
                    local vless_link="vless://${uuid}@${ip_address}:${listen_port}?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=${server_name}&fp=chrome#${remark}"
                    echo "$vless_link" >> "$temp_file"
                fi
            fi
        fi
    done
    
    if [ -s "$temp_file" ]; then
        local base64_content=$(base64 -w 0 "$temp_file")
        echo "$(tput setaf 6)$base64_content$(tput sgr0)"
    else
        echo "$(tput setaf 1)无法生成有效的链接$(tput sgr0)"
    fi
    
    rm -f "$temp_file"
}

# 更新路由规则，修复jq语法错误
modify_routing_rules() {
    echo "正在更新路由规则..."
    local config_dir="/etc/sing-box/conf"
    local main_config="/etc/sing-box/config.json"
    
    # 备份主配置文件
    cp "$main_config" "$main_config.bak.$(date +%Y%m%d%H%M%S)"
    
    # 收集所有入站tag
    local inbound_tags=()
    for file in "$config_dir"/*.json; do
        if [ -f "$file" ]; then
            local filename=$(basename "$file")
            local tag=$(jq -r '.inbounds[0].tag' "$file" 2>/dev/null || echo "$filename")
            inbound_tags+=("$tag")
        fi
    done
    
    # 手动生成JSON字符串，避免jq语法问题
    echo "生成路由规则..."
    
    # 生成一个临时文件作为基础配置
    local temp_config=$(mktemp)
    cp "$main_config" "$temp_config"
    
    # 首先清理已有的socks相关出站
    # 获取当前所有的出站标签
    local existing_outbounds=$(jq '.outbounds // []' "$temp_config")
    local new_outbounds="[]"
    
    # 仅保留不含socks-out前缀的出站
    if [ "$(echo "$existing_outbounds" | jq 'length')" -gt 0 ]; then
        new_outbounds="["
        local outbound_count=$(echo "$existing_outbounds" | jq 'length')
        for i in $(seq 0 $((outbound_count - 1))); do
            local outbound=$(echo "$existing_outbounds" | jq ".[$i]")
            local tag=$(echo "$outbound" | jq -r '.tag // ""')
            
            # 如果标签不以socks-out开头，则保留
            if [[ "$tag" != "socks-out"* ]]; then
                new_outbounds+="$outbound"
                # 如果不是最后一个元素，添加逗号
                if [ $i -lt $((outbound_count - 1)) ]; then
                    new_outbounds+=","
                fi
            fi
        done
        new_outbounds+="]"
        
        # 更新outbounds
        jq ".outbounds = $new_outbounds" "$temp_config" > "$temp_config.new" && mv "$temp_config.new" "$temp_config"
    fi
    
    # 检查是否存在outbounds部分
    if ! jq -e '.outbounds' "$temp_config" > /dev/null 2>&1; then
        # 如果没有outbounds，添加一个空数组
        jq '. += {"outbounds":[]}' "$temp_config" > "$temp_config.new" && mv "$temp_config.new" "$temp_config"
    fi
    
    # 添加一个主WARP SOCKS代理出站
    if ! jq -e '.outbounds[] | select(.tag == "socks-out-main")' "$temp_config" > /dev/null 2>&1; then
        jq '.outbounds += [{"type":"socks","tag":"socks-out-main","server":"127.0.0.1","server_port":1080}]' "$temp_config" > "$temp_config.new" && mv "$temp_config.new" "$temp_config"
    fi
    
    # 添加direct出站（如果不存在）
    if ! jq -e '.outbounds[] | select(.tag == "direct-out-main")' "$temp_config" > /dev/null 2>&1; then
        jq '.outbounds += [{"type":"direct","tag":"direct-out-main"}]' "$temp_config" > "$temp_config.new" && mv "$temp_config.new" "$temp_config"
    fi
    
    # 创建路由规则
    if ! jq -e '.route' "$temp_config" > /dev/null 2>&1; then
        # 如果没有route，添加一个空对象
        jq '. += {"route":{}}' "$temp_config" > "$temp_config.new" && mv "$temp_config.new" "$temp_config"
    fi
    
    # 创建rules数组 - 所有入站都使用同一个socks-out-main出站
    local rules_array="["
    for tag in "${inbound_tags[@]}"; do
        rules_array+="{\"inbound\":[\"$tag\"],\"outbound\":\"socks-out-main\"},"
    done
    # 移除最后一个逗号
    rules_array=${rules_array%,}
    rules_array+="]"
    
    # 更新路由规则和final
    jq --argjson rules "$rules_array" '.route.rules = $rules | .route.final = "direct-out-main"' "$temp_config" > "$temp_config.new" && mv "$temp_config.new" "$temp_config"
    
    # 应用更改到主配置
    mv "$temp_config" "$main_config"
    
    echo "路由规则已更新，所有入站流量将经过WARP代理出站"
}

# 替换update_main_config_json函数调用
main() {
    check_and_install_tools

    check_and_install_singbox

    if ! check_docker_installed; then
        echo "Docker未安装，正在安装Docker..."
        install_docker
    else
        echo "Docker已安装。"
    fi

    if ! check_warp_container; then
        echo "Warp容器未找到，正在安装Warp容器..."
        install_warp_container
    else
        echo "Warp容器已安装。"
    fi

    # 修改Hysteria2配置文件
    modify_hysteria2_config
    echo "配置文件已修改为使用WARP代理出站。"
    
    # 添加主配置修改 - 使用新函数替换原来的
    # update_main_config_json 
    modify_routing_rules
    
    # 检查WARP代理状态
    check_warp_socks_proxy
    
    # 生成并打印所有协议的链接
    generate_subscription
}

# 手动检查WARP SOCKS代理
check_warp_proxy() {
    check_warp_socks_proxy
}

# 清理可能存在的冲突配置
cleanup_configs() {
    echo "正在清理可能的冲突配置..."
    
    # 停止sing-box服务
    systemctl stop sing-box
    
    # 清理主配置文件中的旧outbounds
    local main_config="/etc/sing-box/config.json"
    if [ -f "$main_config" ]; then
        # 备份配置
        cp "$main_config" "$main_config.backup.$(date +%Y%m%d%H%M%S)"
        
        # 移除socks-out标签相关内容
        if jq -e '.outbounds[] | select(.tag == "socks-out")' "$main_config" > /dev/null 2>&1; then
            echo "正在移除主配置中的旧socks-out标签..."
            jq '.outbounds = [.outbounds[] | select(.tag != "socks-out")]' "$main_config" > "$main_config.tmp" && mv "$main_config.tmp" "$main_config"
        fi
    fi
    
    echo "配置清理完成"
}

# 卸载WARP和恢复原始配置
uninstall_warp() {
    echo "==============================================="
    echo "       卸载 WARP 代理和还原配置"
    echo "==============================================="
    
    # 询问用户是否要卸载WARP容器
    read -p "是否要卸载WARP容器？这将移除WARP SOCKS代理 [y/N]: " remove_warp_container
    remove_warp_container=${remove_warp_container:-n}
    
    if [[ "${remove_warp_container,,}" == "y" ]]; then
        echo "正在停止并移除WARP容器..."
        docker stop warp &>/dev/null
        docker rm warp &>/dev/null
        docker rmi caomingjun/warp &>/dev/null
        rm -rf /mnt/warp &>/dev/null
        echo "$(tput setaf 2)WARP容器已移除$(tput sgr0)"
    else
        echo "保留WARP容器，可以手动使用或供其他应用程序使用。"
    fi
    
    # 询问用户是否要还原配置文件
    read -p "是否要还原所有配置文件为原始状态？这将移除WARP代理出站配置 [y/N]: " restore_configs
    restore_configs=${restore_configs:-n}
    
    if [[ "${restore_configs,,}" == "y" ]]; then
        echo "正在还原配置文件..."
        
        # 停止sing-box服务
        systemctl stop sing-box
        
        # 恢复主配置文件
        local main_config="/etc/sing-box/config.json"
        if [ -f "$main_config.backup."* ]; then
            local latest_backup=$(ls -t "$main_config.backup."* | head -n1)
            if [ -f "$latest_backup" ]; then
                cp "$latest_backup" "$main_config"
                echo "已恢复主配置文件($main_config)为备份版本"
            fi
        else
            # 如果没有备份，则生成新的默认配置
            jq '{
                log: {level:"info", timestamp:true},
                outbounds: [
                    {tag:"direct", type:"direct"},
                    {tag:"block", type:"block"}
                ]
            }' <<< {} > "$main_config"
            echo "已重置主配置文件为默认配置"
        fi
        
        # 询问用户是否要恢复原始协议配置文件
        read -p "是否要恢复原始协议配置文件(如Hysteria2, VLESS等)？[y/N]: " restore_protocol_configs
        restore_protocol_configs=${restore_protocol_configs:-n}
        
        if [[ "${restore_protocol_configs,,}" == "y" ]]; then
            local config_dir="/etc/sing-box/conf"
            echo "正在处理协议配置文件..."
            
            for file in "$config_dir"/*.json; do
                if [ -f "$file" ]; then
                    local filename=$(basename "$file")
                    local protocol=$(echo "$filename" | cut -d'-' -f1)
                    
                    # 从文件中提取入站配置
                    local inbounds=$(jq '.inbounds' "$file")
                    
                    # 创建新的配置，仅保留入站配置，使用默认出站
                    jq "{
                        log: {level:\"info\", timestamp:true},
                        inbounds: $inbounds,
                        outbounds: [
                            {tag:\"direct-$filename\", type:\"direct\"},
                            {tag:\"block-$filename\", type:\"block\"}
                        ],
                        route: {
                            rules: [
                                {
                                    inbound: [\"$filename\"],
                                    outbound: \"direct-$filename\"
                                }
                            ],
                            final: \"direct-$filename\"
                        }
                    }" <<< {} > "$file"
                    
                    echo "已重置协议配置文件: $filename"
                fi
            done
        fi
        
        # 重启sing-box服务
        systemctl restart sing-box
        echo "$(tput setaf 2)所有配置已还原，sing-box服务已重启$(tput sgr0)"
    else
        echo "保留当前配置文件。"
    fi
    
    echo "==============================================="
    echo "      卸载操作已完成"
    echo "==============================================="
    
    # 提供使用说明
    if [[ "${remove_warp_container,,}" != "y" ]]; then
        echo "WARP容器仍在运行。如果您想在将来手动移除它，请运行:"
        echo "$(tput setaf 6)docker stop warp && docker rm warp && docker rmi caomingjun/warp && rm -rf /mnt/warp$(tput sgr0)"
    fi
}

main

# 重启sing-box服务
systemctl restart sing-box && echo "sing-box服务已重启。"

# 提示用户可以手动检查WARP代理
echo -e "\n$(tput setaf 3)您可以随时运行以下命令检查WARP代理状态:$(tput sgr0)"
echo -e "$(tput setaf 6)curl --socks5 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace$(tput sgr0)"
echo -e "$(tput setaf 6)curl --socks5 127.0.0.1:1080 https://api.ipify.org$(tput sgr0)"
echo -e "$(tput setaf 6)docker logs warp$(tput sgr0)"
echo -e "$(tput setaf 3)如果需要重新检查WARP代理状态，请运行:$(tput sgr0)"
echo -e "$(tput setaf 6)bash docker-warp.sh check$(tput sgr0)"

# 在脚本结尾处增加卸载说明
echo -e "$(tput setaf 3)如需卸载WARP代理配置，请运行:$(tput sgr0)"
