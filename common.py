#!/usr/bin/env python3
import csv
import os
import logging
import requests
import zipfile
import json
import re
import shutil
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

CURRENT_DIR = os.getcwd()
ASN_URL = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key={}&suffix=zip'

ASN_V4 = defaultdict(list)
ASN_V6 = defaultdict(list)

RULE_FIELDS = (
    'domain',
    'domain_keyword',
    'domain_suffix',
    'domain_regex',
    'ip_cidr',
    'process_name',
    'domain_wildcard',
    'classical',
)
KNOWN_RULE_TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX', 'IP-CIDR', 'IP-CIDR6', 'PROCESS-NAME'}
DEFAULT_NAME_PREFIXES = ('domain_', 'ipcidr_', 'classical_')
DEFAULT_NAME_SUFFIXES = ('_domain', '_domains', '_ipcidr', '_ip_cidr')
SPECIAL_USE_EXACT_DOMAINS = {'bogon', 'example', 'internal', 'invalid', 'lan', 'local', 'localdomain', 'localhost', 'm2m', 'test'}
SPECIAL_USE_SUFFIX_DOMAINS = SPECIAL_USE_EXACT_DOMAINS | {'home.arpa'}

EXCLUDED_RULES = {'adsfix', 'ads-add'}
RULE_TARGET_RENAMES = {
    'directfix': 'Direct',
}

# ---------- 名称归一化 ----------
def strip_rule_name(name: str, extra_prefixes=None, extra_suffixes=None) -> str:
    if not name or not isinstance(name, str):
        return ''

    value = name.strip()
    prefixes = list(DEFAULT_NAME_PREFIXES)
    suffixes = list(DEFAULT_NAME_SUFFIXES)

    if extra_prefixes:
        prefixes.extend(extra_prefixes)
    if extra_suffixes:
        suffixes.extend(extra_suffixes)

    changed = True
    while value and changed:
        changed = False
        lower_value = value.lower()

        for prefix in prefixes:
            if prefix and lower_value.startswith(prefix.lower()) and len(value) > len(prefix):
                value = value[len(prefix):].strip()
                changed = True
                lower_value = value.lower()
                break

        for suffix in suffixes:
            if suffix and lower_value.endswith(suffix.lower()) and len(value) > len(suffix):
                value = value[:-len(suffix)].strip()
                changed = True
                break

    return value.strip(' _-.')


def normalize_name(name: str) -> str:
    """
    将规则集名称转换为稳定的合并键。
    默认忽略大小写、分隔符差异，并去除常见 domain / ipcidr / classical 前缀及常见后缀。
    """
    stripped = strip_rule_name(name)
    return re.sub(r'[^0-9a-z]+', '', stripped.lower())


def should_replace_rule_name(current: str, candidate: str) -> bool:
    if not current:
        return True
    if not candidate or current == candidate:
        return False

    current_is_lower = current == current.lower()
    candidate_is_lower = candidate == candidate.lower()
    if current_is_lower and not candidate_is_lower:
        return True

    if normalize_name(current) == normalize_name(candidate) and len(candidate) < len(current):
        return True

    return False


def resolve_rule_identity(upstream: dict, source_name: str):
    stripped_name = strip_rule_name(
        source_name,
        upstream.get('strip_prefixes'),
        upstream.get('strip_suffixes')
    )

    rename_map = upstream.get('name_map', {})
    target_name = None
    for candidate in (source_name, stripped_name, normalize_name(source_name)):
        if candidate in rename_map:
            target_name = rename_map[candidate]
            break

    if not target_name:
        target_name = stripped_name or source_name.strip()

    target_name = target_name.strip()
    merge_key = normalize_name(target_name)
    if not merge_key:
        merge_key = normalize_name(source_name)

    return merge_key, target_name


def resolve_additional_targets(upstream: dict, source_name: str, target_name: str):
    extra_targets = upstream.get('extra_targets', {})
    if not extra_targets:
        return []

    source_keys = (
        normalize_name(source_name),
        normalize_name(target_name),
    )

    targets = []
    seen = set()
    primary_key = normalize_name(target_name)
    for source_key in source_keys:
        if not source_key:
            continue
        for extra_target in extra_targets.get(source_key, []):
            cleaned_target = extra_target.strip()
            extra_key = normalize_name(cleaned_target)
            if not extra_key or extra_key == primary_key or extra_key in seen:
                continue
            seen.add(extra_key)
            targets.append((extra_key, cleaned_target))

    return targets


def apply_catalog_policy(source_name: str, target_name: str):
    source_key = normalize_name(source_name)
    target_key = normalize_name(target_name)

    if source_key in EXCLUDED_RULES or target_key in EXCLUDED_RULES:
        return None, None

    renamed_target = RULE_TARGET_RENAMES.get(source_key) or RULE_TARGET_RENAMES.get(target_key)
    if renamed_target:
        return normalize_name(renamed_target), renamed_target

    return target_key, target_name

# ---------- 有效性验证 ----------
def is_valid_domain(domain: str) -> bool:
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.strip()
    if (
        not domain
        or domain.startswith('.')
        or domain.endswith('.')
        or ' ' in domain
        or ',' in domain
        or '*' in domain
    ):
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
    if (
        not suffix
        or suffix.startswith('.')
        or suffix.endswith('.')
        or ' ' in suffix
        or ',' in suffix
        or '*' in suffix
    ):
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
    return s if is_valid_domain_suffix(s) else None


def clean_domain_keyword(keyword: str) -> str:
    if not keyword or not isinstance(keyword, str):
        return None
    value = keyword.strip().strip('.')
    if not value or ',' in value or '*' in value:
        return None
    return value


def clean_domain_regex(pattern: str) -> str:
    if not pattern or not isinstance(pattern, str):
        return None
    value = pattern.strip()
    return value or None


def clean_process_name(name: str) -> str:
    if not name or not isinstance(name, str):
        return None
    value = name.strip()
    if not value or ',' in value:
        return None
    return value


def is_valid_ip_cidr(cidr: str) -> bool:
    if not cidr or not isinstance(cidr, str):
        return False
    cidr = cidr.strip()
    if not cidr or ' ' in cidr or '/' not in cidr:
        return False
    ip_part, mask_part = cidr.split('/', 1)
    if not mask_part.isdigit():
        return False
    if '.' in ip_part:
        octets = ip_part.split('.')
        if len(octets) != 4 or not all(o.isdigit() for o in octets):
            return False
    elif ':' not in ip_part:
        return False
    return True


def clean_ip_cidr(cidr: str) -> str:
    if not cidr or not isinstance(cidr, str):
        return None
    value = cidr.strip()
    if ',no-resolve' in value:
        value = value.split(',')[0].strip()
    return value if is_valid_ip_cidr(value) else None


def wildcard_to_regex(pattern: str) -> str:
    escaped = re.escape(pattern)
    return '^' + escaped.replace(r'\*', '.*') + '$'


def exact_domain_to_regex(domain: str) -> str:
    return '^' + re.escape(domain) + '$'


def domain_suffix_to_regex(suffix: str) -> str:
    return r'(^|.+\.)' + re.escape(suffix) + '$'


def should_use_exact_domain_regex(domain: str) -> bool:
    return domain.lower() in SPECIAL_USE_EXACT_DOMAINS


def should_use_domain_suffix_regex(suffix: str) -> bool:
    return suffix.lower() in SPECIAL_USE_SUFFIX_DOMAINS


def strip_quoted_value(value: str) -> str:
    if not value or not isinstance(value, str):
        return value

    cleaned = value.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'\'', '"'}:
        return cleaned[1:-1].strip()
    return cleaned


def clean_domain_wildcard(pattern: str) -> str:
    if not pattern or not isinstance(pattern, str):
        return None

    value = strip_quoted_value(pattern)
    if not value or ' ' in value or ',' in value:
        return None

    if value == '*':
        return value

    if value.startswith('+.'):
        cleaned = clean_domain_suffix(value[2:])
        return f'+.{cleaned}' if cleaned else None

    if value.startswith('.'):
        cleaned = clean_domain_suffix(value[1:])
        return f'.{cleaned}' if cleaned else None

    if '*' not in value:
        cleaned = clean_domain(value)
        return cleaned

    labels = value.split('.')
    if any(not label for label in labels):
        return None

    has_wildcard = False
    for label in labels:
        if label == '*':
            has_wildcard = True
            continue
        if '*' in label:
            return None

    return value if has_wildcard else None


def clean_classical_rule(rule: str) -> str:
    if not rule or not isinstance(rule, str):
        return None

    value = strip_quoted_value(rule)
    if not value or ',' not in value:
        return None

    rule_type, rule_content = value.split(',', 1)
    rule_type = rule_type.strip().upper()
    rule_content = rule_content.strip()
    if (
        not re.match(r'^[A-Z][A-Z0-9-]*$', rule_type)
        or not rule_content
        or rule_type in {'RULE-SET', 'SUB-RULE'}
    ):
        return None

    return f'{rule_type},{rule_content}'


def append_domain_set_value(raw_value: str, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical):
    if not raw_value or not isinstance(raw_value, str):
        return False

    value = strip_quoted_value(raw_value)
    if not value:
        return False

    cleaned = clean_domain_wildcard(value)
    if not cleaned:
        return False

    if cleaned.startswith('+.'):
        domain_suffix.append(cleaned[2:])
    elif cleaned.startswith('.') or cleaned == '*' or '*' in cleaned:
        domain_wildcard.append(cleaned)
    else:
        domain.append(cleaned)
    return True


def append_rule_value(raw_value: str, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical, collect_classical=True):
    if not raw_value or not isinstance(raw_value, str):
        return

    value = strip_quoted_value(raw_value)
    if not value:
        return

    if ',' in value:
        rule_type, rule_content = value.split(',', 1)
        rule_type = rule_type.strip().upper()
        rule_content = rule_content.strip()

        cleaned_rule = clean_classical_rule(f'{rule_type},{rule_content}')
        if cleaned_rule and collect_classical:
            classical.append(cleaned_rule)

        if rule_type == 'DOMAIN':
            cleaned = clean_domain(rule_content)
            if cleaned:
                domain.append(cleaned)
            return
        if rule_type == 'DOMAIN-SUFFIX':
            cleaned = clean_domain_suffix(rule_content)
            if cleaned:
                domain_suffix.append(cleaned)
            return
        if rule_type == 'DOMAIN-KEYWORD':
            cleaned = clean_domain_keyword(rule_content)
            if cleaned:
                domain_keyword.append(cleaned)
            return
        if rule_type == 'DOMAIN-REGEX':
            cleaned = clean_domain_regex(rule_content)
            if cleaned:
                domain_regex.append(cleaned)
            return
        if rule_type in ('IP-CIDR', 'IP-CIDR6'):
            cleaned = clean_ip_cidr(rule_content)
            if cleaned:
                ip_cidr.append(cleaned)
            return
        if rule_type == 'PROCESS-NAME':
            cleaned = clean_process_name(rule_content)
            if cleaned:
                process_name.append(cleaned)
            return
        return

    cleaned = clean_ip_cidr(value)
    if cleaned:
        ip_cidr.append(cleaned)
        return

    if append_domain_set_value(value, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical):
        return

    cleaned = clean_domain_keyword(value)
    if cleaned:
        domain_keyword.append(cleaned)


def append_typed_rule_value(rule_type: str, raw_value: str, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical, collect_classical=True):
    if not raw_value or not isinstance(raw_value, str):
        return

    value = raw_value.strip()
    if not value:
        return

    candidate_type = value.split(',', 1)[0].strip().upper() if ',' in value else ''
    if candidate_type in KNOWN_RULE_TYPES:
        append_rule_value(value, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical, collect_classical=collect_classical)
    else:
        append_rule_value(
            f'{rule_type},{value}',
            domain,
            domain_keyword,
            domain_suffix,
            domain_regex,
            ip_cidr,
            process_name,
            domain_wildcard,
            classical,
            collect_classical=collect_classical,
        )

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
    domain = []
    domain_keyword = []
    domain_suffix = []
    domain_regex = []
    ip_cidr = []
    process_name = []
    domain_wildcard = []
    classical = []
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        for rule in data.get('rules', []):
            for d in rule.get('domain', []):
                append_typed_rule_value('DOMAIN', d, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical, collect_classical=False)
            for dk in rule.get('domain_keyword', []):
                append_typed_rule_value('DOMAIN-KEYWORD', dk, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical, collect_classical=False)
            for ds in rule.get('domain_suffix', []):
                append_typed_rule_value('DOMAIN-SUFFIX', ds, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical, collect_classical=False)
            for dr in rule.get('domain_regex', []):
                append_typed_rule_value('DOMAIN-REGEX', dr, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical, collect_classical=False)
            for ip in rule.get('ip_cidr', []):
                append_typed_rule_value('IP-CIDR', ip, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical, collect_classical=False)
            for pn in rule.get('process_name', []):
                append_typed_rule_value('PROCESS-NAME', pn, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical, collect_classical=False)
    except Exception as e:
        logging.error(f'解析 sing-box JSON 失败（{path}）：{type(e).__name__}: {e}')
    return domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical


def parse_list_file(file_path: str):
    domain = []
    domain_keyword = []
    domain_suffix = []
    domain_regex = []
    ip_cidr = []
    process_name = []
    domain_wildcard = []
    classical = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                append_rule_value(line, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical)
    except Exception as e:
        logging.error(f'解析 list 文件失败（{file_path}）：{e}')
    return domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical


def parse_clash_yaml(file_path: str):
    domain = []
    domain_keyword = []
    domain_suffix = []
    domain_regex = []
    ip_cidr = []
    process_name = []
    domain_wildcard = []
    classical = []
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
                    line = line[2:].strip()
                if not line:
                    continue

                splits = line.split(',')
                if len(splits) >= 2:
                    rule_type = splits[0].strip().upper()
                    rule_content = ','.join(splits[1:]).strip()
                    if rule_type == 'IP-ASN':
                        try:
                            asn_num = int(rule_content)
                            ip_cidr.extend(ASN_V4[asn_num])
                            ip_cidr.extend(ASN_V6[asn_num])
                        except ValueError:
                            logging.warning(f'无效 ASN 编号：{rule_content}')
                    else:
                        append_rule_value(
                            f'{rule_type},{rule_content}',
                            domain,
                            domain_keyword,
                            domain_suffix,
                            domain_regex,
                            ip_cidr,
                            process_name,
                            domain_wildcard,
                            classical,
                        )
                    continue

                append_rule_value(
                    line,
                    domain,
                    domain_keyword,
                    domain_suffix,
                    domain_regex,
                    ip_cidr,
                    process_name,
                    domain_wildcard,
                    classical,
                    collect_classical=False,
                )
    except Exception as e:
        logging.error(f'解析 Clash YAML 失败（{file_path}）：{e}')
    return domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical

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


def reset_output_directory(path: str):
    if os.path.isdir(path):
        for entry in os.listdir(path):
            target = os.path.join(path, entry)
            if os.path.isdir(target):
                shutil.rmtree(target)
            else:
                os.remove(target)
    elif os.path.exists(path):
        os.remove(path)
        os.makedirs(path, exist_ok=True)
    else:
        os.makedirs(path, exist_ok=True)

    logging.info(f'已清理输出目录：{path}')


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
                for sub_entry in os.listdir(source_dir):
                    sub_dir = os.path.join(source_dir, sub_entry)
                    if os.path.isdir(sub_dir):
                        name = sub_entry
                        source_file = os.path.join(sub_dir, f'{sub_entry}.yaml')
                        classical_file = os.path.join(sub_dir, f'{sub_entry}_Classical.yaml')
                        data = None
                        if os.path.exists(source_file):
                            data = parse_clash_yaml(source_file)
                        if os.path.exists(classical_file):
                            data = merge_rule_data(data, parse_clash_yaml(classical_file))
                        if data and any(data):
                            yield name, data
            else:
                name = entry
                source_file = os.path.join(source_dir, f'{entry}.yaml')
                classical_file = os.path.join(source_dir, f'{entry}_Classical.yaml')
                data = None
                if os.path.exists(source_file):
                    data = parse_clash_yaml(source_file)
                if os.path.exists(classical_file):
                    data = merge_rule_data(data, parse_clash_yaml(classical_file))
                if data and any(data):
                    yield name, data

    elif upstream['type'] == 'singbox_json':
        for fname in os.listdir(rules_root):
            if not fname.endswith('.json'):
                continue
            name = fname[:-5]
            path = os.path.join(rules_root, fname)
            data = parse_singbox_json(path)
            yield name, data

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
                    yield name, data

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
                    yield name, ([], [], [], [], ip_cidr, [], [], [])
        geosite_dir = os.path.join(rules_root, 'geosite')
        if os.path.isdir(geosite_dir):
            for fname in os.listdir(geosite_dir):
                if not fname.endswith('.txt'):
                    continue
                name = f'geosite_{fname[:-4]}'
                file_path = os.path.join(geosite_dir, fname)
                domain = []
                domain_keyword = []
                domain_suffix = []
                domain_regex = []
                domain_wildcard = []
                classical = []
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        append_rule_value(line, domain, domain_keyword, domain_suffix, domain_regex, [], [], domain_wildcard, classical)
                if domain or domain_keyword or domain_suffix or domain_regex or domain_wildcard:
                    yield name, (domain, domain_keyword, domain_suffix, domain_regex, [], [], domain_wildcard, [])
    else:
        logging.warning(f'未知上游类型：{upstream["type"]}，跳过')


def merge_unique_values(*groups):
    merged = []
    seen = set()
    for group in groups:
        for value in group:
            if value not in seen:
                seen.add(value)
                merged.append(value)
    return merged


def empty_rule_data():
    return tuple([] for _ in RULE_FIELDS)


def normalize_rule_data(data):
    if not data:
        return empty_rule_data()

    values = [list(group) for group in data[:len(RULE_FIELDS)]]
    while len(values) < len(RULE_FIELDS):
        values.append([])
    return tuple(values)


def merge_rule_data(existing, new):
    existing = normalize_rule_data(existing)
    new = normalize_rule_data(new)

    merged = []
    for old_values, new_values in zip(existing, new):
        merged.append(merge_unique_values(old_values, new_values))
    return tuple(merged)


def upsert_catalog_entry(catalog, merge_key, target_name, data, upstream_name, source_name, note=''):
    if merge_key in catalog:
        entry = catalog[merge_key]
        entry['data'] = merge_rule_data(entry['data'], data)
        if should_replace_rule_name(entry['name'], target_name):
            entry['name'] = target_name
        entry['sources'].append({'upstream': upstream_name, 'name': source_name})
        action = '合并规则集'
    else:
        entry = {
            'name': target_name,
            'data': merge_rule_data(empty_rule_data(), data),
            'sources': [{'upstream': upstream_name, 'name': source_name}],
        }
        catalog[merge_key] = entry
        action = '新增规则集'

    suffix = f'（{note}）' if note else ''
    logging.info(f'[{upstream_name}] {action}：{source_name} -> {entry["name"]}{suffix}')
    return entry


def build_rule_catalog(upstreams=None):
    if upstreams is None:
        upstreams = load_upstreams()

    catalog = {}
    for upstream in upstreams:
        rules_root = download_and_extract(upstream)
        for source_name, data in iter_rules(upstream, rules_root):
            merge_key, target_name = resolve_rule_identity(upstream, source_name)
            if not merge_key:
                logging.warning(f'[{upstream["name"]}] 跳过空规则名：{source_name}')
                continue

            merge_key, target_name = apply_catalog_policy(source_name, target_name)
            if not merge_key:
                logging.info(f'[{upstream["name"]}] 跳过规则集：{source_name}')
                continue

            upsert_catalog_entry(catalog, merge_key, target_name, data, upstream['name'], source_name)

            for extra_key, extra_target in resolve_additional_targets(upstream, source_name, target_name):
                extra_key, extra_target = apply_catalog_policy(source_name, extra_target)
                if not extra_key:
                    logging.info(f'[{upstream["name"]}] 跳过附加目标：{source_name} -> {extra_target}')
                    continue
                upsert_catalog_entry(
                    catalog,
                    extra_key,
                    extra_target,
                    data,
                    upstream['name'],
                    source_name,
                    note=f'附加并入 {extra_target}'
                )

    return catalog

# ---------- sing-box 数据结构 ----------
class SingBoxRuleSet(object):
    def __init__(self, domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, *_):
        self.version = 2
        self.rules = []
        if domain or domain_keyword or domain_suffix or domain_regex:
            rule = {}
            if domain:
                rule['domain'] = sorted(set(domain))
            if domain_keyword:
                rule['domain_keyword'] = sorted(set(domain_keyword))
            if domain_suffix:
                rule['domain_suffix'] = sorted(set(domain_suffix))
            if domain_regex:
                rule['domain_regex'] = sorted(set(domain_regex))
            self.rules.append(rule)
        if ip_cidr:
            self.rules.append({'ip_cidr': sorted(set(ip_cidr))})
        if process_name:
            self.rules.append({'process_name': sorted(set(process_name))})
