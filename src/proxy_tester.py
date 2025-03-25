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
TEST_URL = 'http://www.gstatic.com/generate_204'  # 更可靠的测试URL
TIMEOUT = 10  # 增加超时时间
SPEED_THRESHOLD = 512  # 降低速度要求(字节/秒)
DEFAULT_BLACKLIST = ['CN', '中国', '移动', '联通', '电信', '广电']

def get_env_list(name, default=None):
    """从环境变量获取列表"""
    value = os.getenv(name)
    if value:
        return [item.strip() for item in value.split(',')]
    return default or []

def decode_v2ray_subscription(content):
    """改进的解码V2Ray订阅内容"""
    try:
        # 尝试自动检测并移除可能的头部信息
        if content.startswith(b'http'):
            content = content.split(b'\n')[-1]
        
        decoded = base64.b64decode(content).decode('utf-8')
        proxies = []
        
        for line in decoded.splitlines():
            line = line.strip()
            if not line:
                continue
                
            # 支持多种协议格式
            if line.startswith('vmess://'):
                try:
                    proxy_json = base64.b64decode(line[8:]).decode('utf-8')
                    proxy = json.loads(proxy_json)
                    proxies.append(proxy)
                except Exception as e:
                    print(f"解码vmess失败: {line[:50]}... 错误: {str(e)}")
            elif line.startswith('ss://'):
                try:
                    proxies.append({'ps': 'SS-Proxy', 'url': line})
                except Exception as e:
                    print(f"解码ss失败: {line[:50]}... 错误: {str(e)}")
            elif line.startswith('trojan://'):
                try:
                    proxies.append({'ps': 'Trojan-Proxy', 'url': line})
                except Exception as e:
                    print(f"解码trojan失败: {line[:50]}... 错误: {str(e)}")
        
        print(f"成功解码 {len(proxies)} 个代理配置")
        return proxies
    except Exception as e:
        print(f"订阅内容解码失败: {str(e)}")
        print(f"原始内容开头: {content[:200] if isinstance(content, str) else content[:200].decode('utf-8', errors='ignore')}")
        return []

def fetch_subscription(url):
    """获取订阅内容，添加重试机制"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                content = response.read()
                print(f"从订阅链接获取到 {len(content)} 字节数据")
                return decode_v2ray_subscription(content)
        except Exception as e:
            print(f"获取订阅失败 (尝试 {attempt + 1}/{max_retries}): {str(e)}")
            if attempt == max_retries - 1:
                return []
            time.sleep(2)

def load_proxies():
    """从订阅链接加载代理配置"""
    subscription_urls = get_env_list('SUBSCRIPTION_URLS')
    if not subscription_urls:
        raise ValueError("未提供订阅链接(SUBSCRIPTION_URLS环境变量)")
    
    all_proxies = []
    for url in subscription_urls:
        print(f"\n正在处理订阅链接: {url}")
        proxies = fetch_subscription(url)
        if proxies:
            print(f"从该订阅解析出 {len(proxies)} 个代理配置")
            all_proxies.extend(proxies)
        else:
            print("⚠️ 从该订阅未解析出任何代理配置")
    
    print(f"\n总共获取到 {len(all_proxies)} 个代理配置")
    return all_proxies

def save_proxies(proxies):
    """保存筛选后的代理配置"""
    os.makedirs('output', exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(proxies, f, indent=2, ensure_ascii=False)
    print(f"\n已保存 {len(proxies)} 个有效代理到 {OUTPUT_FILE}")

def is_proxy_valid(proxy):
    """检查代理是否有效"""
    blacklist = get_env_list('BLACKLIST_KEYWORDS', DEFAULT_BLACKLIST)
    name = proxy.get('ps', '').upper()
    
    # 检查黑名单关键词
    for keyword in blacklist:
        if keyword.upper() in name:
            print(f"过滤掉代理(黑名单关键词): {name}")
            return False
    
    # 检查必要字段
    required_fields = ['add', 'port']
    for field in required_fields:
        if field not in proxy:
            print(f"过滤掉代理(缺少{field}字段): {name}")
            return False
    
    return True

def test_latency(host, port):
    """测试TCP延迟，添加详细错误处理"""
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.close()
        latency = (time.time() - start) * 1000
        print(f"延迟测试成功: {host}:{port} - {latency:.2f}ms")
        return latency
    except socket.timeout:
        print(f"延迟测试超时: {host}:{port}")
        return None
    except socket.error as e:
        print(f"延迟测试失败: {host}:{port} - 错误: {str(e)}")
        return None

def test_speed(proxy_config):
    """测试代理速度，改进测试方法"""
    proxy_str = f"{proxy_config['add']}:{proxy_config['port']}"
    proxy_name = proxy_config.get('ps', proxy_str)
    
    # 根据协议类型使用不同的代理设置
    if 'url' in proxy_config:  # SS/Trojan等非vmess协议
        print(f"跳过速度测试(非vmess协议): {proxy_name}")
        return SPEED_THRESHOLD * 2  # 直接通过
    
    proxy_settings = {
        'http': f"socks5://{proxy_str}",
        'https': f"socks5://{proxy_str}"
    }
    
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(proxy_settings)
    )
    
    try:
        start_time = time.time()
        response = opener.open(TEST_URL, timeout=TIMEOUT)
        content = response.read()
        elapsed = time.time() - start_time
        speed = len(content) / elapsed
        
        print(f"速度测试成功: {proxy_name} - {speed/1024:.2f}KB/s")
        return speed
    except URLError as e:
        print(f"速度测试失败(URL错误): {proxy_name} - {str(e)}")
        return 0
    except socket.timeout:
        print(f"速度测试超时: {proxy_name}")
        return 0
    except Exception as e:
        print(f"速度测试异常: {proxy_name} - {str(e)}")
        return 0

def test_proxy(proxy):
    """测试单个代理，添加详细日志"""
    proxy_name = proxy.get('ps', f"{proxy.get('add', '')}:{proxy.get('port', '')}")
    print(f"\n开始测试代理: {proxy_name}")
    
    if not is_proxy_valid(proxy):
        return None
    
    # 测试延迟
    latency = test_latency(proxy['add'], proxy['port'])
    if latency is None:
        return None
    
    # 测试速度
    speed = test_speed(proxy)
    if speed < SPEED_THRESHOLD:
        print(f"代理速度不足: {speed/1024:.2f}KB/s < {SPEED_THRESHOLD/1024:.2f}KB/s")
        return None
    
    print(f"代理测试通过: {proxy_name} - 延迟: {latency:.2f}ms, 速度: {speed/1024:.2f}KB/s")
    return {
        **proxy,
        'latency': latency,
        'speed': speed
    }

def main():
    print("=== 开始代理测试任务 ===")
    
    # 加载代理配置
    print("\n步骤1: 从订阅链接加载代理配置")
    proxies = load_proxies()
    
    if not proxies:
        print("⚠️ 错误: 未加载到任何代理配置")
        save_proxies([])
        return
    
    # 测试代理
    print(f"\n步骤2: 测试 {len(proxies)} 个代理")
    valid_proxies = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:  # 减少并发数以避免被封
        futures = {executor.submit(test_proxy, proxy): proxy for proxy in proxies}
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_proxies.append(result)
    
    # 结果处理
    print(f"\n步骤3: 结果汇总")
    print(f"测试完成: 共 {len(proxies)} 个代理，{len(valid_proxies)} 个有效")
    
    if valid_proxies:
        # 按延迟排序
        valid_proxies.sort(key=lambda x: x['latency'])
        
        # 移除测试添加的字段
        for proxy in valid_proxies:
            proxy.pop('latency', None)
            proxy.pop('speed', None)
        
        # 保存结果
        save_proxies(valid_proxies)
    else:
        print("⚠️ 警告: 没有有效的代理通过测试")
        save_proxies([])
    
    print("\n=== 任务完成 ===")

if __name__ == '__main__':
    main()