#!/bin/bash

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

    # 清理可能的冲突配置
    cleanup_configs
    
    # 修改所有配置文件
    modify_hysteria2_config
    echo "所有协议配置文件已修改，出站流量都将经过127.0.0.1:1080端口"
    
    # 修改主配置文件
    update_main_config_json
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

# 更新主配置文件以支持WARP
update_main_config_json() {
    local main_config="/etc/sing-box/config.json"
    if [ -f "$main_config" ]; then
        echo "正在更新主配置文件..."
        
        # 备份当前配置
        cp "$main_config" "$main_config.bak"
        
        # 读取当前配置中的outbounds部分
        local current_outbounds=$(jq '.outbounds' "$main_config")
        
        # 检查是否已存在socks-out-main标签
        if ! echo "$current_outbounds" | grep -q '"tag":"socks-out-main"'; then
            # 创建新的outbounds配置
            local new_outbounds='[
  {
    "type": "socks",
    "tag": "socks-out-main",
    "server": "127.0.0.1",
    "server_port": 1080
  },'
            
            # 添加原有的其他outbound
            for i in $(seq 0 $(($(echo "$current_outbounds" | jq 'length') - 1))); do
                local outbound=$(echo "$current_outbounds" | jq ".[$i]")
                new_outbounds+="$outbound"
                if [ $i -lt $(($(echo "$current_outbounds" | jq 'length') - 1)) ]; then
                    new_outbounds+=","
                fi
            done
            
            new_outbounds+="]"
            
            # 更新配置文件
            jq ".outbounds = $new_outbounds" "$main_config" > "$main_config.tmp" && mv "$main_config.tmp" "$main_config"
            echo "主配置文件已更新，添加了WARP代理出站"
        else
            echo "主配置文件中已存在WARP代理出站设置"
        fi
        
        # 更新路由规则
        update_main_route "$main_config"
    else
        echo "主配置文件不存在，跳过更新"
    fi
}

# 更新主配置文件的路由规则
update_main_route() {
    local main_config="$1"
    echo "正在更新路由规则..."
    
    # 获取所有配置文件名称作为入站标签
    local inbound_tags=()
    local config_dir="/etc/sing-box/conf"
    for file in "$config_dir"/*.json; do
        if [ -f "$file" ]; then
            local filename=$(basename "$file")
            inbound_tags+=("$filename")
        fi
    done
    
    # 检查配置文件中是否已有route部分
    if jq -e '.route' "$main_config" > /dev/null 2>&1; then
        # 已有route，检查是否有rules
        if jq -e '.route.rules' "$main_config" > /dev/null 2>&1; then
            # 已有rules，添加新规则
            local rules_json="["
            
            # 为每个入站添加路由规则
            for tag in "${inbound_tags[@]}"; do
                rules_json+="{\"inbound\":[\"$tag\"],\"outbound\":\"socks-out-$tag\"},"
            done
            
            # 添加已有规则
            local current_rules=$(jq '.route.rules' "$main_config")
            for i in $(seq 0 $(($(echo "$current_rules" | jq 'length') - 1))); do
                local rule=$(echo "$current_rules" | jq ".[$i]")
                
                # 跳过与我们添加的规则重复的规则
                local skip=false
                for tag in "${inbound_tags[@]}"; do
                    if echo "$rule" | grep -q "\"inbound\":\[\"$tag\"\]"; then
                        skip=true
                        break
                    fi
                done
                
                if ! $skip; then
                    rules_json+="$rule,"
                fi
            done
            
            # 移除最后一个逗号并关闭数组
            rules_json=$(echo "$rules_json" | sed 's/,$//')
            rules_json+="]"
            
            # 更新路由规则
            jq ".route.rules = $rules_json" "$main_config" > "$main_config.tmp" && mv "$main_config.tmp" "$main_config"
            
            # 设置默认出站为direct-out
            jq '.route.final = "direct-out-main"' "$main_config" > "$main_config.tmp" && mv "$main_config.tmp" "$main_config"
        else
            # 没有rules，创建新的rules
            local rules_json="["
            for tag in "${inbound_tags[@]}"; do
                rules_json+="{\"inbound\":[\"$tag\"],\"outbound\":\"socks-out-$tag\"},"
            done
            # 移除最后一个逗号并关闭数组
            rules_json=$(echo "$rules_json" | sed 's/,$//')
            rules_json+="]"
            
            # 更新路由规则
            jq ".route += {\"rules\":$rules_json, \"final\":\"direct-out-main\"}" "$main_config" > "$main_config.tmp" && mv "$main_config.tmp" "$main_config"
        fi
    else
        # 没有route，创建新的route
        local rules_json="["
        for tag in "${inbound_tags[@]}"; do
            rules_json+="{\"inbound\":[\"$tag\"],\"outbound\":\"socks-out-$tag\"},"
        done
        # 移除最后一个逗号并关闭数组
        rules_json=$(echo "$rules_json" | sed 's/,$//')
        rules_json+="]"
        
        # 添加route部分
        jq ". += {\"route\":{\"rules\":$rules_json, \"final\":\"direct-out-main\"}}" "$main_config" > "$main_config.tmp" && mv "$main_config.tmp" "$main_config"
    fi
    
    # 确保主配置中有direct-out-main
    if ! jq -e '.outbounds[] | select(.tag == "direct-out-main")' "$main_config" > /dev/null 2>&1; then
        # 添加direct-out-main
        jq '.outbounds += [{"type":"direct","tag":"direct-out-main"}]' "$main_config" > "$main_config.tmp" && mv "$main_config.tmp" "$main_config"
    fi
    
    echo "路由规则已更新，所有入站流量将经过WARP代理出站"
}

main

# 重启sing-box服务
systemctl restart sing-box && echo "sing-box服务已重启。"
