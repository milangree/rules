#!/usr/bin/env python3
import os
import json
import logging
from common import (
    CURRENT_DIR, init_asn, load_upstreams, download_and_extract, iter_rules,
    SingBoxRuleSet
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SINGBOX_DIR = os.path.join(CURRENT_DIR, 'rules', 'singbox')
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

def write_singbox_rule(name, data):
    sb_dir = os.path.join(SINGBOX_DIR, name)
    os.makedirs(sb_dir, exist_ok=True)
    rule_set = SingBoxRuleSet(*data)
    json_path = os.path.join(sb_dir, f'{name}.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(rule_set, f, default=lambda obj: obj.__dict__, sort_keys=True, indent=2)

    # 写 README
    content = '\n'.join([
        f'# {name}',
        '',
        '#### 规则链接',
        '',
        '**sing-box**',
        f'`{RAW_BASE}/singbox/{name}/{name}.srs`',
        f'`https://cdn.jsdelivr.net/gh/{REPO}@main/rules/singbox/{name}/{name}.srs`',
    ]) + '\n'
    with open(os.path.join(sb_dir, 'README.md'), 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    init_asn()
    upstreams = load_upstreams()
    for upstream in upstreams:
        process_upstream(upstream)
    for name, data in rules_data.items():
        write_singbox_rule(name, data)
    logging.info(f'sing-box 规则集生成完毕，共 {len(rules_data)} 个')

if __name__ == '__main__':
    main()
