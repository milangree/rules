#!/usr/bin/env python3
import os
import logging
from common import (
    CURRENT_DIR, init_asn, load_upstreams, download_and_extract, iter_rules,
    is_valid_domain, is_valid_domain_suffix, is_valid_ip_cidr
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MIHOMO_DIR = os.path.join(CURRENT_DIR, 'rules', 'mihomo')
REPO = 'milangree/rules'
RAW_BASE = f'https://raw.githubusercontent.com/{REPO}/main/rules'

rules_data = {}

def merge_rule_data(existing, new):
    return (
        list(set(existing[0]) | set(new[0])),
        list(set(existing[1]) | set(new[1])),
        list(set(existing[2]) | set(new[2])),
        list(set(existing[3]) | set(new[3])),
        list(set(existing[4]) | set(new[4]))
    )

def process_upstream(upstream):
    global rules_data
    rules_root = download_and_extract(upstream)
    for name, data in iter_rules(upstream, rules_root):
        if name in rules_data:
            rules_data[name] = merge_rule_data(rules_data[name], data)
            logging.info(f'[{upstream["name"]}] 合并规则集：{name}')
        else:
            rules_data[name] = data
            logging.info(f'[{upstream["name"]}] 新增规则集：{name}')

def write_mihomo_yaml(path, entries):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('payload:\n')
        for entry in sorted(set(entries)):
            f.write(f"  - {entry}\n")

def write_mihomo_rule(name, data):
    domain, domain_keyword, domain_suffix, ip_cidr, _ = data
    mh_dir = os.path.join(MIHOMO_DIR, name)
    os.makedirs(mh_dir, exist_ok=True)

    domain_entries = []
    for d in set(domain):
        if is_valid_domain(d):
            domain_entries.append(d)
    for ds in set(domain_suffix):
        if is_valid_domain_suffix(ds):
            domain_entries.append(f'+.{ds}')
    for dk in set(domain_keyword):
        if dk:
            domain_entries.append(dk.strip())
    ip_entries = [ip for ip in set(ip_cidr) if is_valid_ip_cidr(ip)]

    if domain_entries:
        write_mihomo_yaml(os.path.join(mh_dir, f'{name}_domain.yaml'), domain_entries)
    if ip_entries:
        write_mihomo_yaml(os.path.join(mh_dir, f'{name}_ipcidr.yaml'), ip_entries)

    # 写 README
    content = '\n'.join([
        f'# {name}',
        '',
        '#### 规则链接',
        '',
        '**mihomo（域名）**',
        f'`{RAW_BASE}/mihomo/{name}/{name}_domain.mrs`',
        f'`{RAW_BASE}/mihomo/{name}/{name}_domain.yaml`',
        '',
        '**mihomo（IP）**',
        f'`{RAW_BASE}/mihomo/{name}/{name}_ipcidr.mrs`',
        f'`{RAW_BASE}/mihomo/{name}/{name}_ipcidr.yaml`',
    ]) + '\n'
    with open(os.path.join(mh_dir, 'README.md'), 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    init_asn()
    upstreams = load_upstreams()
    for upstream in upstreams:
        process_upstream(upstream)
    for name, data in rules_data.items():
        write_mihomo_rule(name, data)
    logging.info(f'mihomo 规则集生成完毕，共 {len(rules_data)} 个')

if __name__ == '__main__':
    main()
