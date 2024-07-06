#!/bin/bash

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
    if [ $(docker ps -a --format '{{.Names}}' | grep -w "warp" | wc -l) -eq 0 ]; then
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
    --health-cmd="nc -z 127.0.0.1 1080" --health-interval=1m30s \
    --health-timeout=10s --health-retries=3 --health-start-period=40s \
    caomingjun/warp
}

# 修改Hysteria2配置文件
modify_hysteria2_config() {
    local config_dir="/etc/sing-box/conf"
    for file in "$config_dir"/Hysteria2-*.json; do
        if [ -f "$file" ]; then
            local filename=$(basename "$file")
            local password=$(jq -r '.inbounds[0].users[0].password' "$file")
            local listen_port=$(jq -r '.inbounds[0].listen_port' "$file")
            
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
      "tag": "socks-out",
      "server": "127.0.0.1",
      "server_port": 1080
    },
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": [
          "$filename"
        ],
        "outbound": "socks-out"
      }
    ],
    "final": "direct-out"
  }
}
EOF
        fi
    done
}

main() {
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
    echo "Hysteria2配置文件已修改。"
}

main

# 重启sing-box服务
systemctl restart sing-box && echo "sing-box服务已重启。"
