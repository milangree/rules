#!/usr/bin/env python3
import csv
import os
import logging
import requests
import zipfile
import json
import re
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

CURRENT_DIR = os.getcwd()
ASN_URL = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key={}&suffix=zip'

ASN_V4 = defaultdict(list)
ASN_V6 = defaultdict(list)

# ---------- 名称归一化 ----------
def normalize_name(name: str) -> str:
    """
    将规则集名称归一化为小写键，用于合并。
    去除常见的 "domain_" 前缀，然后转为小写。
    """
    name = name.lower()
    if name.startswith('domain_'):
        name = name[7:]
    return name

# ---------- 有效性验证 ----------
def is_valid_domain(domain: str) -> bool:
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.strip()
    if not domain or domain.startswith('.') or domain.endswith('.') or ' ' in domain:
        return False
    if re.match(r'^[\d\.]+$', domain) and '.' in domain:
        parts = domain.split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return False
    return True

def is_valid_domain_suffix(suffix: str) -> bool:
    if not suffix or not isinstance(suffix, str):
        return False
    suffix = suffix.strip()
    if not suffix or suffix.startswith('.') or suffix.endswith('.') or ' ' in suffix:
        return False
    return True

def clean_domain(domain: str) -> str:
    if not domain:
        return None
    d = domain.strip()
    return d if is_valid_domain(d) else None

def clean_domain_suffix(suffix: str) -> str:
    if not suffix:
        return None
    s = suffix.strip()
    if s.startswith('+.'):
        s = s[2:]
    return s if is_valid_domain(s) else None

def is_valid_ip_cidr(cidr: str) -> bool:
    if not cidr or not isinstance(cidr, str):
        return False
    cidr = cidr.strip()
    if not cidr or ' ' in cidr or '/' not in cidr:
        return False
    ip_part, mask_part = cidr.split('/')
    if not mask_part.isdigit():
        return False
    if '.' in ip_part:
        octets = ip_part.split('.')
        if len(octets) != 4 or not all(o.isdigit() for o in octets):
            return False
    elif ':' not in ip_part:
        return False
    return True

# ---------- ASN 初始化 ----------
def init_asn():
    maxmind_key = os.environ.get('MAXMIND_KEY')
    if not maxmind_key or not maxmind_key.strip():
        logging.critical('MAXMIND_KEY 未设置！')
        exit(1)

    zip_path = os.path.join(CURRENT_DIR, 'asn.zip')
    if os.path.exists(zip_path):
        logging.info('检测到缓存的 ASN 文件，跳过下载')
    else:
        logging.info('正在下载 ASN 文件...')
        response = requests.get(ASN_URL.format(maxmind_key), headers=HEADERS)
        if response.status_code == 200:
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            logging.info('ASN 文件下载完成')
        else:
            logging.critical(f'ASN 文件下载失败，状态码：{response.status_code}')
            exit(1)

    asn_folder = os.path.join(CURRENT_DIR, 'asn')
    if os.path.exists(asn_folder) and os.path.isdir(asn_folder):
        logging.info('ASN 已解压，跳过')
    else:
        os.makedirs(asn_folder, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            file_list = zip_ref.namelist()
            outer_folder = file_list[0].split('/')[0]
            for file_name in file_list:
                if file_name.startswith(outer_folder + '/'):
                    stripped = file_name[len(outer_folder) + 1:]
                    if not stripped:
                        continue
                    target = os.path.join(asn_folder, stripped)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, 'wb') as out:
                        out.write(zip_ref.read(file_name))
        logging.info(f'ASN 文件解压完成：{asn_folder}')

    global ASN_V4, ASN_V6
    asn_v4_file = os.path.join(asn_folder, 'GeoLite2-ASN-Blocks-IPv4.csv')
    asn_v6_file = os.path.join(asn_folder, 'GeoLite2-ASN-Blocks-IPv6.csv')
    with open(asn_v4_file, mode='r', encoding='utf-8') as f:
        csv_reader = csv.reader(f, delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            if row and len(row) >= 2:
                ASN_V4[int(row[1])].append(row[0])
    with open(asn_v6_file, mode='r', encoding='utf-8') as f:
        csv_reader = csv.reader(f, delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            if row and len(row) >= 2:
                ASN_V6[int(row[1])].append(row[0])
    logging.info('ASN 信息汇总完成')

# ---------- 规则解析 ----------
def parse_singbox_json(path: str):
    domain = []; domain_keyword = []; domain_suffix = []
    ip_cidr = []; process_name = []
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        for rule in data.get('rules', []):
            for d in rule.get('domain', []):
                cleaned = clean_domain(d)
                if cleaned:
                    domain.append(cleaned)
            for dk in rule.get('domain_keyword', []):
                if dk and isinstance(dk, str):
                    domain_keyword.append(dk.strip())
            for ds in rule.get('domain_suffix', []):
                cleaned = clean_domain_suffix(ds)
                if cleaned:
                    domain_suffix.append(cleaned)
            for ip in rule.get('ip_cidr', []):
                if is_valid_ip_cidr(ip):
                    ip_cidr.append(ip.strip())
            for pn in rule.get('process_name', []):
                if pn and isinstance(pn, str):
                    process_name.append(pn.strip())
    except Exception as e:
        logging.error(f'解析 sing-box JSON 失败（{path}）：{type(e).__name__}: {e}')
    return domain, domain_keyword, domain_suffix, ip_cidr, process_name

def parse_list_file(file_path: str):
    domain = []; domain_suffix = []; ip_cidr = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if is_valid_ip_cidr(line):
                    ip_cidr.append(line)
                elif line.startswith('+.'):
                    cleaned = clean_domain_suffix(line[2:])
                    if cleaned:
                        domain_suffix.append(cleaned)
                else:
                    cleaned = clean_domain(line)
                    if cleaned:
                        domain.append(cleaned)
    except Exception as e:
        logging.error(f'解析 list 文件失败（{file_path}）：{e}')
    return domain, [], domain_suffix, ip_cidr, []

def parse_clash_yaml(file_path: str):
    domain = []; domain_keyword = []; domain_suffix = []; ip_cidr = []; process_name = []
    try:
        found_payload = False
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if 'payload:' in line.strip():
                    found_payload = True
                    continue
                if not found_payload:
                    continue
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('- '):
                    line = line[2:]
                splits = line.split(',')
                if len(splits) < 2:
                    continue
                rule_type, rule_content = splits[0], ','.join(splits[1:])
                if rule_type == 'DOMAIN':
                    cleaned = clean_domain(rule_content)
                    if cleaned:
                        domain.append(cleaned)
                elif rule_type == 'DOMAIN-SUFFIX':
                    cleaned = clean_domain_suffix(rule_content)
                    if cleaned:
                        domain_suffix.append(cleaned)
                elif rule_type == 'DOMAIN-KEYWORD':
                    if rule_content:
                        domain_keyword.append(rule_content.strip())
                elif rule_type in ('IP-CIDR', 'IP-CIDR6'):
                    # 去除 ,no-resolve 后缀
                    if ',no-resolve' in rule_content:
                        rule_content = rule_content.split(',')[0]
                    if is_valid_ip_cidr(rule_content):
                        ip_cidr.append(rule_content.strip())
                elif rule_type == 'IP-ASN':
                    try:
                        asn_num = int(rule_content)
                        ip_cidr.extend(ASN_V4[asn_num])
                        ip_cidr.extend(ASN_V6[asn_num])
                    except ValueError:
                        logging.warning(f'无效 ASN 编号：{rule_content}')
                elif rule_type == 'PROCESS-NAME':
                    if rule_content:
                        process_name.append(rule_content.strip())
                else:
                    logging.warning(f'未知规则类型：{rule_type}')
    except Exception as e:
        logging.error(f'解析 Clash YAML 失败（{file_path}）：{e}')
    return domain, domain_keyword, domain_suffix, ip_cidr, process_name

# ---------- 通用上游处理 ----------
def load_upstreams():
    config_path = os.path.join(CURRENT_DIR, 'upstreams.json')
    if not os.path.exists(config_path):
        logging.critical('未找到 upstreams.json 配置文件')
        exit(1)
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def download_and_extract(upstream):
    zip_path = os.path.join(CURRENT_DIR, upstream['zip_name'])
    if os.path.exists(zip_path):
        logging.info(f'使用缓存的 {upstream["zip_name"]}')
    else:
        logging.info(f'正在下载 {upstream["name"]} ...')
        response = requests.get(upstream['url'], headers=HEADERS)
        if response.status_code == 200:
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            logging.info(f'{upstream["name"]} 下载完成')
        else:
            logging.critical(f'{upstream["name"]} 下载失败，状态码：{response.status_code}')
            exit(1)

    extract_dir = os.path.join(CURRENT_DIR, upstream['extract_folder'])
    if os.path.exists(extract_dir):
        logging.info(f'{upstream["extract_folder"]} 已存在，跳过解压')
    else:
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        logging.info(f'{upstream["name"]} 解压完成：{extract_dir}')

    subpath = upstream['rules_subpath']
    if '*' in subpath:
        items = os.listdir(extract_dir)
        top_dirs = [d for d in items if os.path.isdir(os.path.join(extract_dir, d))]
        if not top_dirs:
            logging.critical(f'{upstream["name"]} 解压后未找到任何目录')
            exit(1)
        top_dir = top_dirs[0]
        subpath = subpath.replace('*', top_dir)
    rules_root = os.path.join(extract_dir, subpath)
    if not os.path.isdir(rules_root):
        logging.critical(f'{upstream["name"]} 规则目录不存在：{rules_root}')
        exit(1)
    return rules_root

def iter_rules(upstream, rules_root):
    if upstream['type'] == 'clash':
        subs = upstream.get('subs', [])
        for entry in os.listdir(rules_root):
            if entry == 'CGB':
                continue
            source_dir = os.path.join(rules_root, entry)
            if not os.path.isdir(source_dir):
                continue
            if entry in subs:
                for subEntry in os.listdir(source_dir):
                    sub_dir = os.path.join(source_dir, subEntry)
                    if os.path.isdir(sub_dir):
                        name = subEntry
                        source_file = os.path.join(sub_dir, f'{subEntry}.yaml')
                        classical = os.path.join(sub_dir, f'{subEntry}_Classical.yaml')
                        if os.path.exists(classical):
                            source_file = classical
                        if os.path.exists(source_file):
                            data = parse_clash_yaml(source_file)
                            yield normalize_name(name), data
            else:
                name = entry
                source_file = os.path.join(source_dir, f'{entry}.yaml')
                classical = os.path.join(source_dir, f'{entry}_Classical.yaml')
                if os.path.exists(classical):
                    source_file = classical
                if os.path.exists(source_file):
                    data = parse_clash_yaml(source_file)
                    yield normalize_name(name), data

    elif upstream['type'] == 'singbox_json':
        for fname in os.listdir(rules_root):
            if not fname.endswith('.json'):
                continue
            name = fname[:-5]
            path = os.path.join(rules_root, fname)
            data = parse_singbox_json(path)
            yield normalize_name(name), data

    elif upstream['type'] == 'mixed':
        for root, _, files in os.walk(rules_root):
            for f in files:
                if f.endswith('.json') or f.endswith('.list') or f.endswith('.txt'):
                    file_path = os.path.join(root, f)
                    rel_path = os.path.relpath(file_path, rules_root)
                    name = rel_path[:-len(os.path.splitext(f)[1])].replace(os.sep, '_')
                    if f.endswith('.json'):
                        data = parse_singbox_json(file_path)
                    else:
                        data = parse_list_file(file_path)
                    yield normalize_name(name), data

    elif upstream['type'] == 'metacubex':
        geoip_dir = os.path.join(rules_root, 'geoip')
        if os.path.isdir(geoip_dir):
            for fname in os.listdir(geoip_dir):
                if not fname.endswith('.txt'):
                    continue
                name = f'geoip_{fname[:-4]}'
                file_path = os.path.join(geoip_dir, fname)
                ip_cidr = []
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and is_valid_ip_cidr(line):
                            ip_cidr.append(line)
                if ip_cidr:
                    yield normalize_name(name), ([], [], [], ip_cidr, [])
        geosite_dir = os.path.join(rules_root, 'geosite')
        if os.path.isdir(geosite_dir):
            for fname in os.listdir(geosite_dir):
                if not fname.endswith('.txt'):
                    continue
                name = f'geosite_{fname[:-4]}'
                file_path = os.path.join(geosite_dir, fname)
                domain = []; domain_suffix = []
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if line.startswith('+.'):
                            cleaned = clean_domain_suffix(line[2:])
                            if cleaned:
                                domain_suffix.append(cleaned)
                        else:
                            cleaned = clean_domain(line)
                            if cleaned:
                                domain.append(cleaned)
                if domain or domain_suffix:
                    yield normalize_name(name), (domain, [], domain_suffix, [], [])
    else:
        logging.warning(f'未知上游类型：{upstream["type"]}，跳过')

# ---------- sing-box 数据结构 ----------
class SingBoxRuleSet(object):
    def __init__(self, domain, domain_keyword, domain_suffix, ip_cidr, process_name):
        self.version = 2
        self.rules = []
        if domain or domain_keyword or domain_suffix:
            rule = {}
            if domain:
                rule['domain'] = sorted(set(domain))
            if domain_keyword:
                rule['domain_keyword'] = sorted(set(domain_keyword))
            if domain_suffix:
                rule['domain_suffix'] = sorted(set(domain_suffix))
            self.rules.append(rule)
        if ip_cidr:
            self.rules.append({'ip_cidr': sorted(set(ip_cidr))})
        if process_name:
            self.rules.append({'process_name': sorted(set(process_name))})
