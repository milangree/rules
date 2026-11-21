#!/usr/bin/env python3
import os
import json
import logging
from common import CURRENT_DIR, init_asn, load_upstreams, build_rule_catalog, reset_output_directory, SingBoxRuleSet

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SINGBOX_DIR = os.path.join(CURRENT_DIR, 'rules', 'singbox')
REPO = 'milangree/rules'
RAW_BASE = f'https://raw.githubusercontent.com/{REPO}/main/rules'


def write_singbox_rule(name, data):
    sb_dir = os.path.join(SINGBOX_DIR, name)
    os.makedirs(sb_dir, exist_ok=True)
    rule_set = SingBoxRuleSet(*data)
    json_path = os.path.join(sb_dir, f'{name}.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(rule_set, f, default=lambda obj: obj.__dict__, sort_keys=True, indent=2)

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
    catalog = build_rule_catalog(upstreams)
    reset_output_directory(SINGBOX_DIR)
    for entry in sorted(catalog.values(), key=lambda item: item['name'].lower()):
        write_singbox_rule(entry['name'], entry['data'])
    logging.info(f'sing-box 规则集生成完毕，共 {len(catalog)} 个')


if __name__ == '__main__':
    main()
