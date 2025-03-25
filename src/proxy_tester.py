import json
import os
import re
import time
import socket
import base64
import urllib.request
from urllib.error import URLError
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
OUTPUT_FILE = os.path.join('output', 'filtered_proxies.json')
TEST_URL = 'http://www.google.com'  # 用于测试的URL
TIMEOUT = 5  # 超时时间(秒)
SPEED_THRESHOLD = 1024  # 最低速度要求(字节/秒)
DEFAULT_BLACKLIST = ['CN', '中国', '移动', '联通', '电信']

def get_env_list(name, default=None):
    """从环境变量获取列表"""
    value = os.getenv(name)
    if value:
        return [item.strip() for item in value.split(',')]
    return default or []

def decode_v2ray_subscription(content):
    """解码V2Ray订阅内容"""
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        proxies = []
        for line in decoded.splitlines():
            if line.startswith('vmess://'):
                proxy_json = base64.b64decode(line[8:]).decode('utf-8')
                proxy = json.loads(proxy_json)
                proxies.append(proxy)
        return proxies
    except Exception as e:
        print(f"Error decoding subscription: {str(e)}")
        return []

def fetch_subscription(url):
    """获取订阅内容"""
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as response:
            return decode_v2ray_subscription(response.read())
    except Exception as e:
        print(f"Error fetching subscription {url}: {str(e)}")
        return []

def load_proxies():
    """从订阅链接加载代理配置"""
    subscription_urls = get_env_list('SUBSCRIPTION_URLS')
    if not subscription_urls:
        raise ValueError("No subscription URLs provided in SUBSCRIPTION_URLS environment variable")
    
    all_proxies = []
    for url in subscription_urls:
        print(f"Fetching proxies from: {url}")
        proxies = fetch_subscription(url)
        all_proxies.extend(proxies)
        print(f"Found {len(proxies)} proxies from this subscription")
    
    return all_proxies

def save_proxies(proxies):
    """保存筛选后的代理配置"""
    os.makedirs('output', exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(proxies, f, indent=2, ensure_ascii=False)

def is_proxy_valid(proxy):
    """检查代理是否包含黑名单关键词"""
    blacklist = get_env_list('BLACKLIST_KEYWORDS', DEFAULT_BLACKLIST)
    name = proxy.get('ps', '').upper()
    for keyword in blacklist:
        if keyword.upper() in name:
            return False
    return True

def test_latency(host, port):
    """测试TCP延迟"""
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.close()
        return (time.time() - start) * 1000  # 转换为毫秒
    except (socket.timeout, socket.error):
        return None

def test_speed(proxy_config):
    """测试代理速度"""
    proxy_str = f"{proxy_config['add']}:{proxy_config['port']}"
    proxy_handler = urllib.request.ProxyHandler({
        'http': f"socks5://{proxy_str}",
        'https': f"socks5://{proxy_str}"
    })
    opener = urllib.request.build_opener(proxy_handler)
    
    start_time = time.time()
    try:
        response = opener.open(TEST_URL, timeout=TIMEOUT)
        content = response.read()
        elapsed = time.time() - start_time
        speed = len(content) / elapsed  # 字节/秒
        return speed
    except (URLError, socket.timeout):
        return 0

def test_proxy(proxy):
    """测试单个代理"""
    if not is_proxy_valid(proxy):
        return None
    
    try:
        latency = test_latency(proxy['add'], proxy['port'])
        if latency is None:
            return None
            
        speed = test_speed(proxy)
        if speed < SPEED_THRESHOLD:
            return None
            
        return {
            **proxy,
            'latency': latency,
            'speed': speed
        }
    except Exception as e:
        print(f"Error testing proxy {proxy.get('ps')}: {str(e)}")
        return None

def main():
    print("Loading proxies from subscriptions...")
    proxies = load_proxies()
    
    print(f"Testing {len(proxies)} proxies...")
    valid_proxies = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_proxy, proxy) for proxy in proxies]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_proxies.append(result)
                print(f"Valid proxy found: {result['ps']} - Latency: {result['latency']:.2f}ms, Speed: {result['speed']/1024:.2f}KB/s")
    
    print(f"Found {len(valid_proxies)} valid proxies out of {len(proxies)}")
    
    # 按延迟排序
    valid_proxies.sort(key=lambda x: x['latency'])
    
    # 移除测试添加的字段
    for proxy in valid_proxies:
        proxy.pop('latency', None)
        proxy.pop('speed', None)
    
    save_proxies(valid_proxies)
    print(f"Results saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()