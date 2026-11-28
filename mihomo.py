#!/usr/bin/env python3
import os
import logging
from common import (
    CURRENT_DIR,
    init_asn,
    load_upstreams,
    build_rule_catalog,
    reset_output_directory,
    is_valid_domain,
    is_valid_domain_suffix,
    is_valid_ip_cidr,
    clean_domain_keyword,
    clean_domain_regex,
    clean_domain_wildcard,
    clean_classical_rule,
    clean_process_name,
    normalize_rule_data,
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MIHOMO_DIR = os.path.join(CURRENT_DIR, 'rules', 'mihomo')
REPO = 'milangree/rules'
RAW_BASE = f'https://raw.githubusercontent.com/{REPO}/main/rules'


def write_mihomo_yaml(path, entries):
    unique_entries = sorted(set(entries))
    if not unique_entries:
        return

    with open(path, 'w', encoding='utf-8') as f:
        f.write('payload:\n')
        for entry in unique_entries:
            f.write(f"  - {entry}\n")


def build_mihomo_domain_entries(data):
    domain, _, domain_suffix, _, _, _, domain_wildcard, _ = normalize_rule_data(data)

    entries = []
    for d in domain:
        if is_valid_domain(d):
            entries.append(d)
    for ds in domain_suffix:
        if is_valid_domain_suffix(ds):
            entries.append(f'+.{ds}')
    for dw in domain_wildcard:
        cleaned = clean_domain_wildcard(dw)
        if cleaned and (cleaned.startswith('.') or cleaned == '*' or '*' in cleaned):
            entries.append(cleaned)
    return entries


def build_mihomo_classical_entries(data):
    domain, domain_keyword, domain_suffix, domain_regex, _, process_name, _, classical = normalize_rule_data(data)

    entries = []
    for d in domain:
        if is_valid_domain(d):
            entries.append(f'DOMAIN,{d}')
    for ds in domain_suffix:
        if is_valid_domain_suffix(ds):
            entries.append(f'DOMAIN-SUFFIX,{ds}')
    for dk in domain_keyword:
        cleaned = clean_domain_keyword(dk)
        if cleaned:
            entries.append(f'DOMAIN-KEYWORD,{cleaned}')
    for dr in domain_regex:
        cleaned = clean_domain_regex(dr)
        if cleaned:
            entries.append(f'DOMAIN-REGEX,{cleaned}')
    for pn in process_name:
        cleaned = clean_process_name(pn)
        if cleaned:
            entries.append(f'PROCESS-NAME,{cleaned}')
    for rule in classical:
        cleaned = clean_classical_rule(rule)
        if cleaned:
            entries.append(cleaned)
    return entries


def build_mihomo_ip_entries(data):
    _, _, _, _, ip_cidr, _, _, _ = normalize_rule_data(data)
    return [ip for ip in set(ip_cidr) if is_valid_ip_cidr(ip)]


def write_mihomo_rule(name, data):
    mh_dir = os.path.join(MIHOMO_DIR, name)
    os.makedirs(mh_dir, exist_ok=True)

    domain_entries = build_mihomo_domain_entries(data)
    classical_entries = build_mihomo_classical_entries(data)
    ip_entries = build_mihomo_ip_entries(data)

    if domain_entries:
        write_mihomo_yaml(os.path.join(mh_dir, f'{name}_domain.yaml'), domain_entries)
    if classical_entries:
        write_mihomo_yaml(os.path.join(mh_dir, f'{name}_classical.yaml'), classical_entries)
    if ip_entries:
        write_mihomo_yaml(os.path.join(mh_dir, f'{name}_ipcidr.yaml'), ip_entries)

    content_lines = [
        f'# {name}',
        '',
        '#### 规则链接',
        '',
    ]

    if domain_entries:
        content_lines.extend([
            '**mihomo（域名）**',
            f'`{RAW_BASE}/mihomo/{name}/{name}_domain.mrs`',
            f'`{RAW_BASE}/mihomo/{name}/{name}_domain.yaml`',
            '',
        ])
    if classical_entries:
        content_lines.extend([
            '**mihomo（Classical）**',
            f'`{RAW_BASE}/mihomo/{name}/{name}_classical.mrs`',
            f'`{RAW_BASE}/mihomo/{name}/{name}_classical.yaml`',
            '',
        ])
    if ip_entries:
        content_lines.extend([
            '**mihomo（IP）**',
            f'`{RAW_BASE}/mihomo/{name}/{name}_ipcidr.mrs`',
            f'`{RAW_BASE}/mihomo/{name}/{name}_ipcidr.yaml`',
        ])

    with open(os.path.join(mh_dir, 'README.md'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(content_lines).rstrip() + '\n')


def main():
    init_asn()
    upstreams = load_upstreams()
    catalog = build_rule_catalog(upstreams)
    reset_output_directory(MIHOMO_DIR)
    for entry in sorted(catalog.values(), key=lambda item: item['name'].lower()):
        write_mihomo_rule(entry['name'], entry['data'])
    logging.info(f'mihomo 规则集生成完毕，共 {len(catalog)} 个')


if __name__ == '__main__':
    main()
