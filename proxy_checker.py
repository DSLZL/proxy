import os
import json
import time
import base64
import socket
import tempfile
import subprocess
import logging
from urllib.parse import urlparse, parse_qs, unquote

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def find_free_port():
    """查找可用本地端口"""
    with socket.socket() as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def parse_proxy(uri):
    """解析代理URI"""
    uri = uri.strip()
    try:
        if uri.startswith('ss://'):
            return parse_ss(uri)
        elif uri.startswith('trojan://'):
            return parse_trojan(uri)
        elif uri.startswith('vless://'):
            return parse_vless(uri)
        return None
    except Exception as e:
        logging.error(f"解析失败: {uri} - {str(e)}")
        return None

def parse_ss(uri):
    """解析Shadowsocks链接"""
    try:
        uri = uri[5:].split('#')[0]  # 去除锚点
        if '@' in uri:
            encoded, server_part = uri.split('@', 1)
        else:
            encoded, server_part = uri, ''

        # Base64解码兼容处理
        for pad in range(3):
            try:
                decoded = base64.urlsafe_b64decode(encoded + '='*pad).decode('utf-8')
                if '@' in decoded:  # 处理含@的特殊情况
                    decoded, server_part = decoded.split('@', 1)
                break
            except:
                continue

        # 解析认证信息
        method, password = decoded.split(':', 1)
        
        # 解析服务器信息
        server_port = server_part.split('?')[0]
        server, port = (server_port.split(':', 1) if ':' in server_port 
                       else (server_port, '8388'))
        
        # 解析查询参数
        query_str = uri.split('?', 1)[1] if '?' in uri else ''
        query = parse_qs(urlparse('?' + query_str).query)

        return {
            'type': 'ss',
            'server': server,
            'port': int(port),
            'method': method,
            'password': password,
            'query': query
        }
    except Exception as e:
        logging.error(f"SS解析错误: {uri} - {str(e)}")
        return None

def parse_trojan(uri):
    """解析Trojan链接"""
    try:
        parsed = urlparse(uri)
        query = parse_qs(parsed.query)
        return {
            'type': 'trojan',
            'server': parsed.hostname,
            'port': parsed.port or 443,
            'password': unquote(parsed.username),
            'sni': query.get('sni', [''])[0],
            'allow_insecure': int(query.get('allowInsecure', [0])[0]),
            'transport': query.get('type', ['tcp'])[0],
            'path': query.get('path', ['/'])[0]
        }
    except Exception as e:
        logging.error(f"Trojan解析错误: {uri} - {str(e)}")
        return None

def parse_vless(uri):
    """解析VLESS链接"""
    try:
        parsed = urlparse(uri)
        query = parse_qs(parsed.query)
        return {
            'type': 'vless',
            'server': parsed.hostname,
            'port': parsed.port or 443,
            'password': unquote(parsed.username),
            'sni': query.get('sni', [''])[0],
            'transport': query.get('type', ['tcp'])[0],
            'path': query.get('path', ['/'])[0],
            'security': query.get('security', ['tls'])[0]
        }
    except Exception as e:
        logging.error(f"VLESS解析错误: {uri} - {str(e)}")
        return None

def test_ss(config):
    """测试Shadowsocks连接"""
    local_port = find_free_port()
    config_file = None
    try:
        # 生成配置文件
        ss_config = {
            "server": config['server'],
            "server_port": config['port'],
            "local_address": "127.0.0.1",
            "local_port": local_port,
            "password": config['password'],
            "method": config['method'],
            "timeout": 5
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            json.dump(ss_config, f)
            config_file = f.name
        
        # 启动客户端
        proc = subprocess.Popen(['ss-local', '-c', config_file],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        time.sleep(2)  # 等待客户端启动
        
        # 测试连接
        result = subprocess.run(
            ['curl', '-sSf', '--connect-timeout', '10', '--retry', '2',
             '-x', f'socks5://127.0.0.1:{local_port}', 
             'https://www.gstatic.com/generate_204'],
            timeout=15,
            capture_output=True
        )
        return result.returncode == 0
    except Exception as e:
        logging.error(f"SS测试错误: {config['server']}:{config['port']} - {str(e)}")
        return False
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
        if config_file and os.path.exists(config_file):
            os.remove(config_file)

def generate_xray_config(config, protocol):
    """生成Xray配置文件"""
    stream_settings = {
        "network": config.get('transport', 'tcp'),
        "security": config.get('security', 'tls'),
        "tlsSettings": {
            "serverName": config['sni'],
            "allowInsecure": config.get('allow_insecure', False)
        }
    }
    
    # WebSocket配置
    if config.get('transport') == 'ws':
        stream_settings["wsSettings"] = {
            "path": config.get('path', '/'),
            "headers": {"Host": config['sni']} if config['sni'] else {}
        }
    
    return {
        "inbounds": [{
            "port": find_free_port(),
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [{
            "protocol": protocol,
            "settings": {
                "vnext" if protocol == "vless" else "servers": [{
                    "address": config['server'],
                    "port": config['port'],
                    "users": [{"id": config['password']}] if protocol == "vless" else 
                    [{"password": config['password']}]
                }]
            },
            "streamSettings": stream_settings
        }]
    }

def test_xray(config, protocol):
    """测试Xray协议连接"""
    config_file = None
    try:
        # 生成临时配置文件
        xray_config = generate_xray_config(config, protocol)
        local_port = xray_config['inbounds'][0]['port']
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            json.dump(xray_config, f)
            config_file = f.name
        
        # 启动Xray
        proc = subprocess.Popen(['xray', '-config', config_file],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        time.sleep(3)  # 等待服务启动
        
        # 测试连接
        result = subprocess.run(
            ['curl', '-sSf', '--connect-timeout', '10', '--retry', '2',
             '-x', f'socks5://127.0.0.1:{local_port}', 
             'https://www.gstatic.com/generate_204'],
            timeout=20,
            capture_output=True
        )
        return result.returncode == 0
    except Exception as e:
        logging.error(f"{protocol}测试错误: {config['server']}:{config['port']} - {str(e)}")
        return False
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
        if config_file and os.path.exists(config_file):
            os.remove(config_file)

def main(input_file, output_file):
    """主函数"""
    logging.info("开始检测代理可用性")
    
    with open(input_file, 'r') as f:
        proxies = [line.strip() for line in f if line.strip()]
    
    available = []
    for idx, line in enumerate(proxies, 1):
        logging.info(f"正在检测 ({idx}/{len(proxies)})：{line[:60]}...")
        config = parse_proxy(line)
        if not config:
            continue
        if test_proxy(config):
            available.append(line)
            logging.info("✅ 可用代理")
        else:
            logging.warning("❌ 不可用代理")
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(available))
    logging.info(f"检测完成，可用代理数：{len(available)}")

def test_proxy(config):
    """代理测试分发"""
    try:
        if config['type'] == 'ss':
            return test_ss(config)
        elif config['type'] in ['trojan', 'vless']:
            return test_xray(config, config['type'])
        return False
    except Exception as e:
        logging.error(f"测试异常: {str(e)}")
        return False

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])