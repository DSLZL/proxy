import os
import json
import time
import base64
import socket
import tempfile
import subprocess
import logging
import threading
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('proxy_check.log')
    ]
)

# 全局配置
MAX_WORKERS = 5  # 并发线程数
TIMEOUT = 25     # 单代理最大检测时间(秒)
TEST_URL = 'https://www.gstatic.com/generate_204'  # 测试目标

class ProxyTester:
    def __init__(self):
        self.available = []
        self.lock = threading.Lock()
        self.total = 0
        self.completed = 0

    @staticmethod
    def parse_proxy(uri):
        """解析代理URI"""
        uri = uri.strip()
        try:
            if uri.startswith('ss://'):
                return ProxyTester.parse_ss(uri)
            elif uri.startswith('trojan://'):
                return ProxyTester.parse_trojan(uri)
            elif uri.startswith('vless://'):
                return ProxyTester.parse_vless(uri)
            return None
        except Exception as e:
            logging.error(f"解析失败: {uri[:60]}... - {str(e)}")
            return None

    @staticmethod
    def parse_ss(uri):
        """解析Shadowsocks链接"""
        try:
            uri = uri[5:].split('#')[0]
            if '@' in uri:
                encoded, server_part = uri.split('@', 1)
            else:
                encoded, server_part = uri, ''

            # Base64解码兼容处理
            for pad in range(3):
                try:
                    decoded = base64.urlsafe_b64decode(encoded + '='*pad).decode('utf-8')
                    if '@' in decoded:
                        decoded, server_part = decoded.split('@', 1)
                    break
                except:
                    continue

            method, password = decoded.split(':', 1)
            server_port = server_part.split('?')[0]
            server, port = (server_port.split(':', 1) if ':' in server_port 
                         else (server_port, '8388'))
            
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
            logging.error(f"SS解析错误: {uri[:60]}... - {str(e)}")
            return None

    @staticmethod
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
            logging.error(f"Trojan解析错误: {uri[:60]}... - {str(e)}")
            return None

    @staticmethod
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
            logging.error(f"VLESS解析错误: {uri[:60]}... - {str(e)}")
            return None

    def test_proxy(self, line):
        """单个代理检测任务"""
        start_time = time.time()
        config = self.parse_proxy(line)
        success = False
        try:
            if not config:
                return line, False

            if config['type'] == 'ss':
                success = self.test_ss(config)
            elif config['type'] in ['trojan', 'vless']:
                success = self.test_xray(config, config['type'])
            else:
                logging.warning(f"未知协议: {config['type']}")
                
        except Exception as e:
            logging.error(f"检测异常: {line[:60]}... - {str(e)}")
        finally:
            self.update_progress()
            duration = time.time() - start_time
            log_msg = f"{'✅' if success else '❌'} {duration:.1f}s | {line[:60]}..."
            logging.info(log_msg) if success else logging.warning(log_msg)
            return line, success

    def update_progress(self):
        """更新进度显示"""
        with self.lock:
            self.completed += 1
            progress = self.completed / self.total * 100
            logging.info(f"进度: {self.completed}/{self.total} ({progress:.1f}%)")

    def test_ss(self, config):
        """测试Shadowsocks连接"""
        local_port = self.find_free_port()
        config_file = None
        try:
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
            
            proc = subprocess.Popen(['ss-local', '-c', config_file],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            time.sleep(2)
            
            try:
                result = subprocess.run(
                    ['curl', '-sSf', '--connect-timeout', '10', '--retry', '2',
                     '-x', f'socks5://127.0.0.1:{local_port}', TEST_URL],
                    timeout=TIMEOUT,
                    capture_output=True
                )
                return result.returncode == 0
            except subprocess.TimeoutExpired:
                return False
            finally:
                proc.terminate()
                proc.wait(timeout=5)
                os.remove(config_file)
        except Exception as e:
            logging.error(f"SS测试错误: {str(e)}")
            return False

    def test_xray(self, config, protocol):
        """测试Xray协议连接"""
        config_file = None
        try:
            xray_config = self.generate_xray_config(config, protocol)
            local_port = xray_config['inbounds'][0]['port']
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                json.dump(xray_config, f)
                config_file = f.name
            
            proc = subprocess.Popen(['xray', '-config', config_file],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            time.sleep(3)
            
            try:
                result = subprocess.run(
                    ['curl', '-sSf', '--connect-timeout', '10', '--retry', '2',
                     '-x', f'socks5://127.0.0.1:{local_port}', TEST_URL],
                    timeout=TIMEOUT,
                    capture_output=True
                )
                return result.returncode == 0
            except subprocess.TimeoutExpired:
                return False
            finally:
                proc.terminate()
                proc.wait(timeout=5)
                os.remove(config_file)
        except Exception as e:
            logging.error(f"Xray测试错误: {str(e)}")
            return False

    @staticmethod
    def generate_xray_config(config, protocol):
        """生成Xray配置文件"""
        stream_settings = {
            "network": config.get('transport', 'tcp'),
            "security": config.get('security', 'tls'),
            "tlsSettings": {
                "serverName": config['sni'],
                "allowInsecure": bool(config.get('allow_insecure', False))
            }
        }
        
        if config.get('transport') == 'ws':
            stream_settings["wsSettings"] = {
                "path": config.get('path', '/'),
                "headers": {"Host": config['sni']} if config['sni'] else {}
            }
        
        return {
            "inbounds": [{
                "port": ProxyTester.find_free_port(),
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

    @staticmethod
    def find_free_port():
        """查找可用本地端口"""
        with socket.socket() as s:
            s.bind(('', 0))
            return s.getsockname()[1]

def main(input_file, output_file):
    """主函数"""
    logging.info("启动代理检测任务")
    
    with open(input_file, 'r') as f:
        proxies = [line.strip() for line in f if line.strip()]
    
    tester = ProxyTester()
    tester.total = len(proxies)
    
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(tester.test_proxy, line) for line in proxies]
        
        for future in as_completed(futures):
            line, success = future.result()
            if success:
                with tester.lock:
                    tester.available.append(line)

    total_time = time.time() - start_time
    logging.info(f"检测完成，总耗时: {total_time//60:.0f}分{total_time%60:.1f}秒")
    logging.info(f"总代理数: {len(proxies)} | 可用代理: {len(tester.available)}")
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(tester.available))
    
    logging.info(f"结果已保存至: {output_file}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])