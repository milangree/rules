import csv
import os
import shutil
import logging
import requests
import zipfile
import json
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

current_dir = os.getcwd()
asn_url = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key={}&suffix=zip'
asn_v4 = defaultdict(list)
asn_v6 = defaultdict(list)

REPO        = 'milangree/rules'
RAW_BASE    = f'https://raw.githubusercontent.com/{REPO}/main/rules'
CDN_BASE    = f'https://cdn.jsdelivr.net/gh/{REPO}@main/rules'
SINGBOX_DIR = os.path.join(current_dir, 'rules', 'singbox')
MIHOMO_DIR  = os.path.join(current_dir, 'rules', 'mihomo')


def init():
    rules_path = os.path.join(current_dir, 'rules')
    if os.path.exists(rules_path) and os.path.isdir(rules_path):
        logging.warning(f'{rules_path} 已存在，正在删除...')
        shutil.rmtree(rules_path)
    os.makedirs(SINGBOX_DIR)
    os.makedirs(MIHOMO_DIR)

    maxmind_key = os.environ.get('MAXMIND_KEY')
    if not maxmind_key or not maxmind_key.strip():
        logging.critical('MAXMIND_KEY 未设置！')
        exit(1)

    # ── ASN 缓存：zip 已存在则跳过下载（由 Actions cache 恢复）─────────────
    zip_path = os.path.join(current_dir, 'asn.zip')
    if os.path.exists(zip_path):
        logging.info('检测到缓存的 ASN 文件，跳过下载')
    else:
        logging.info('正在下载 ASN 文件...')
        response = requests.get(asn_url.format(maxmind_key), headers=headers)
        if response.status_code == 200:
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            logging.info('ASN 文件下载完成')
        else:
            logging.critical(f'ASN 文件下载失败，状态码：{response.status_code}')
            exit(1)

    asn_folder_path = os.path.join(current_dir, 'asn')
    os.makedirs(asn_folder_path, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        file_list = zip_ref.namelist()
        outer_folder = file_list[0].split('/')[0]
        for file_name in file_list:
            if file_name.startswith(outer_folder + '/'):
                stripped = file_name[len(outer_folder) + 1:]
                if not stripped:
                    continue
                target = os.path.join(asn_folder_path, stripped)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, 'wb') as out:
                    out.write(zip_ref.read(file_name))
    logging.info(f'ASN 文件解压完成：{asn_folder_path}')

    asn_v4_file = os.path.join(asn_folder_path, 'GeoLite2-ASN-Blocks-IPv4.csv')
    asn_v6_file = os.path.join(asn_folder_path, 'GeoLite2-ASN-Blocks-IPv6.csv')
    with open(asn_v4_file, mode='r', encoding='utf-8') as f:
        csv_reader = csv.reader(f, delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            if not row or len(row) < 2:
                continue
            asn_v4[int(row[1])].append(row[0])
    with open(asn_v6_file, mode='r', encoding='utf-8') as f:
        csv_reader = csv.reader(f, delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            if not row or len(row) < 2:
                continue
            asn_v6[int(row[1])].append(row[0])
    logging.info('ASN 信息汇总完成')


# ── 上游一：blackmatrix7 Clash 规则集 ──────────────────────────────────────

source_repo_url = 'https://github.com/blackmatrix7/ios_rule_script/archive/refs/heads/master.zip'

def download_source_repo():
    logging.info('正在下载上游规则源文件（blackmatrix7）...')
    source_zip = os.path.join(current_dir, 'ios_rule_script.zip')
    response = requests.get(source_repo_url, headers=headers)
    if response.status_code == 200:
        with open(source_zip, 'wb') as f:
            f.write(response.content)
        logging.info('上游规则源文件下载完成')
    else:
        logging.critical(f'上游规则源下载失败，状态码：{response.status_code}')
        exit(1)
    source_folder = os.path.join(current_dir, 'ios_rule_script')
    os.makedirs(source_folder, exist_ok=True)
    with zipfile.ZipFile(source_zip, 'r') as zip_ref:
        zip_ref.extractall(source_folder)
    logging.info(f'上游规则源解压完成：{source_folder}')


# ── 上游二：ljrgov/conf sing-box 规则集 ────────────────────────────────────

ljrgov_repo_url   = 'https://github.com/ljrgov/conf/archive/refs/heads/main.zip'
ljrgov_rules_path = 'conf-main/conf/sing-box/rules'   # zip 内路径（去掉顶层目录后）

def download_ljrgov_repo():
    logging.info('正在下载上游规则源文件（ljrgov/conf）...')
    source_zip = os.path.join(current_dir, 'ljrgov_conf.zip')
    response = requests.get(ljrgov_repo_url, headers=headers)
    if response.status_code == 200:
        with open(source_zip, 'wb') as f:
            f.write(response.content)
        logging.info('ljrgov/conf 下载完成')
    else:
        logging.critical(f'ljrgov/conf 下载失败，状态码：{response.status_code}')
        exit(1)
    source_folder = os.path.join(current_dir, 'ljrgov_conf')
    os.makedirs(source_folder, exist_ok=True)
    with zipfile.ZipFile(source_zip, 'r') as zip_ref:
        zip_ref.extractall(source_folder)
    logging.info(f'ljrgov/conf 解压完成：{source_folder}')


# ── sing-box JSON 结构 ─────────────────────────────────────────────────────
#
# 【修复】domain/suffix/keyword 与 ip_cidr 必须放在不同 rule 对象中。
# sing-box 对同一对象内的条件做 AND 匹配，不同对象之间是 OR 匹配。
# 将它们分开后，域名规则和 IP 规则各自独立命中，行为才正确。

class SingBoxRuleSet(object):
    def __init__(self, domain, domain_keyword, domain_suffix, ip_cidr, process_name):
        self.version = 2
        self.rules = []
        # 域名规则：独立一个 rule 对象
        if domain or domain_keyword or domain_suffix:
            rule = {}
            if domain:
                rule['domain'] = sorted(set(domain))
            if domain_keyword:
                rule['domain_keyword'] = sorted(set(domain_keyword))
            if domain_suffix:
                rule['domain_suffix'] = sorted(set(domain_suffix))
            self.rules.append(rule)
        # IP 规则：独立一个 rule 对象（与域名规则 OR 匹配）
        if ip_cidr:
            self.rules.append({'ip_cidr': sorted(set(ip_cidr))})
        # 进程规则：独立一个 rule 对象
        if process_name:
            self.rules.append({'process_name': sorted(set(process_name))})


# ── mihomo YAML payload 写入 ───────────────────────────────────────────────

def _write_mihomo_yaml(path, entries):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('payload:\n')
        for entry in sorted(set(entries)):
            f.write(f"  - '{entry}'\n")


# ── sing-box JSON 解析（用于读取 ljrgov/conf 的已有规则）──────────────────

def _parse_singbox_json(path: str) -> tuple:
    """
    解析 sing-box ruleset JSON 文件，返回
    (domain, domain_keyword, domain_suffix, ip_cidr, process_name)
    支持 rules 数组中有多个 rule 对象（分别提取后合并）。
    """
    domain = []; domain_keyword = []; domain_suffix = []
    ip_cidr = []; process_name = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for rule in data.get('rules', []):
            domain.extend(rule.get('domain', []))
            domain_keyword.extend(rule.get('domain_keyword', []))
            domain_suffix.extend(rule.get('domain_suffix', []))
            ip_cidr.extend(rule.get('ip_cidr', []))
            process_name.extend(rule.get('process_name', []))
    except Exception as e:
        logging.warning(f'解析 sing-box JSON 失败（{path}）：{e}')
    return domain, domain_keyword, domain_suffix, ip_cidr, process_name


# ── 规则转换核心（blackmatrix7） ───────────────────────────────────────────

subs = ["Assassin'sCreed", "Cloud"]

def translate_rule():
    source_folder = os.path.join(current_dir, 'ios_rule_script/ios_rule_script-master/rule/Clash')
    for entry in os.listdir(source_folder):
        if entry == 'CGB':
            continue
        source_dir = os.path.join(source_folder, entry)
        if not os.path.isdir(source_dir):
            continue
        if entry in subs:
            for subEntry in os.listdir(source_dir):
                _translate(subEntry, os.path.join(source_dir, subEntry))
        else:
            _translate(entry, source_dir)
    logging.info('Clash 规则转换完成')


def _translate(entry, source_dir):
    sb_dir = os.path.join(SINGBOX_DIR, entry)
    mh_dir = os.path.join(MIHOMO_DIR,  entry)
    os.makedirs(sb_dir, exist_ok=True)
    os.makedirs(mh_dir, exist_ok=True)

    source_file = os.path.join(source_dir, f'{entry}.yaml')
    classical   = os.path.join(source_dir, f'{entry}_Classical.yaml')
    if os.path.exists(classical):
        source_file = classical

    domain = []; domain_keyword = []; domain_suffix = []; ip_cidr = []; process_name = []

    found_payload = False
    with open(source_file, 'r', encoding='utf-8') as f:
        for line in f:
            if 'payload:' in line.strip():
                found_payload = True
                continue
            if not found_payload:
                continue
            splits = line.strip()[2:].split(',')
            if len(splits) < 2:
                continue
            rule_type, rule_content = splits[0], splits[1]
            if rule_type == 'DOMAIN':
                domain.append(rule_content)
            elif rule_type == 'DOMAIN-SUFFIX':
                domain_suffix.append(rule_content)
            elif rule_type == 'DOMAIN-KEYWORD':
                domain_keyword.append(rule_content)
            elif rule_type in ('IP-CIDR', 'IP-CIDR6'):
                ip_cidr.append(rule_content)
            elif rule_type == 'IP-ASN':
                ip_cidr.extend(asn_v4[int(rule_content)])
                ip_cidr.extend(asn_v6[int(rule_content)])
            elif rule_type == 'PROCESS-NAME':
                process_name.append(rule_content)
            else:
                logging.warning(f'未知规则类型：{rule_type}')

    _write_singbox(entry, sb_dir, domain, domain_keyword, domain_suffix, ip_cidr, process_name)
    _write_mihomo(entry, mh_dir, domain, domain_keyword, domain_suffix, ip_cidr)
    _write_readme(entry, sb_dir, mh_dir)


# ── 规则转换核心（ljrgov/conf） ────────────────────────────────────────────

def translate_ljrgov():
    """
    读取 ljrgov/conf 的 sing-box JSON 规则，解析后同时输出：
      - rules/singbox/<name>/<name>.json（重新生成，ip_cidr 已修复分组）
      - rules/mihomo/<name>/<name>_domain.yaml
      - rules/mihomo/<name>/<name>_ipcidr.yaml
    若 blackmatrix7 已生成同名规则，ljrgov 的数据会与其合并（取并集）。
    """
    rules_dir = os.path.join(current_dir, 'ljrgov_conf', ljrgov_rules_path)
    if not os.path.isdir(rules_dir):
        logging.error(f'ljrgov/conf 规则目录不存在：{rules_dir}')
        return

    count = 0
    for fname in sorted(os.listdir(rules_dir)):
        if not fname.endswith('.json'):
            continue
        name = fname[:-5]  # 去掉 .json
        path = os.path.join(rules_dir, fname)

        domain, domain_keyword, domain_suffix, ip_cidr, process_name = _parse_singbox_json(path)

        if not any([domain, domain_keyword, domain_suffix, ip_cidr, process_name]):
            logging.warning(f'[ljrgov] {name} 无有效规则，跳过')
            continue

        sb_dir = os.path.join(SINGBOX_DIR, name)
        mh_dir = os.path.join(MIHOMO_DIR,  name)

        # 若 blackmatrix7 已生成同名规则，读出已有数据并合并
        existing_json = os.path.join(sb_dir, f'{name}.json')
        if os.path.exists(existing_json):
            ex = _parse_singbox_json(existing_json)
            domain         = list(set(domain)         | set(ex[0]))
            domain_keyword = list(set(domain_keyword) | set(ex[1]))
            domain_suffix  = list(set(domain_suffix)  | set(ex[2]))
            ip_cidr        = list(set(ip_cidr)        | set(ex[3]))
            process_name   = list(set(process_name)   | set(ex[4]))
            logging.info(f'[ljrgov] {name} 与已有规则合并')
        else:
            os.makedirs(sb_dir, exist_ok=True)
            os.makedirs(mh_dir, exist_ok=True)

        _write_singbox(name, sb_dir, domain, domain_keyword, domain_suffix, ip_cidr, process_name)
        _write_mihomo( name, mh_dir, domain, domain_keyword, domain_suffix, ip_cidr)
        _write_readme( name, sb_dir, mh_dir)
        count += 1

    logging.info(f'ljrgov/conf 规则转换完成，共处理 {count} 个规则集')


# ── 公共输出函数 ───────────────────────────────────────────────────────────

def _write_singbox(entry, target_dir, domain, domain_keyword, domain_suffix, ip_cidr, process_name):
    rule_set = SingBoxRuleSet(domain, domain_keyword, domain_suffix, ip_cidr, process_name)
    with open(os.path.join(target_dir, f'{entry}.json'), 'w', encoding='utf-8') as f:
        json.dump(rule_set, f, default=lambda obj: obj.__dict__, sort_keys=True, indent=2)


def _write_mihomo(entry, target_dir, domain, domain_keyword, domain_suffix, ip_cidr):
    domain_entries = []
    for d in set(domain):
        domain_entries.append(f'DOMAIN,{d}')
    for d in set(domain_suffix):
        domain_entries.append(f'DOMAIN-SUFFIX,{d}')
    for d in set(domain_keyword):
        domain_entries.append(f'DOMAIN-KEYWORD,{d}')

    ipcidr_entries = []
    for c in set(ip_cidr):
        prefix = 'IP-CIDR6' if ':' in c else 'IP-CIDR'
        ipcidr_entries.append(f'{prefix},{c}')

    if domain_entries:
        _write_mihomo_yaml(os.path.join(target_dir, f'{entry}_domain.yaml'), domain_entries)
    if ipcidr_entries:
        _write_mihomo_yaml(os.path.join(target_dir, f'{entry}_ipcidr.yaml'), ipcidr_entries)


def _write_readme(entry, sb_dir, mh_dir):
    content = '\n'.join([
        f'# {entry}',
        '',
        '#### 规则链接',
        '',
        '**sing-box**',
        f'`{RAW_BASE}/singbox/{entry}/{entry}.srs`',
        f'`{CDN_BASE}/singbox/{entry}/{entry}.srs`',
        '',
        '**mihomo（域名）**',
        f'`{RAW_BASE}/mihomo/{entry}/{entry}_domain.mrs`',
        f'`{RAW_BASE}/mihomo/{entry}/{entry}_domain.yaml`',
        '',
        '**mihomo（IP）**',
        f'`{RAW_BASE}/mihomo/{entry}/{entry}_ipcidr.mrs`',
        f'`{RAW_BASE}/mihomo/{entry}/{entry}_ipcidr.yaml`',
    ]) + '\n'
    for d in (sb_dir, mh_dir):
        with open(os.path.join(d, 'README.md'), 'w', encoding='utf-8') as f:
            f.write(content)


# ── 额外 Surge 规则 ────────────────────────────────────────────────────────

extra_surge_conf = {}

def translate_extra():
    if not extra_surge_conf:
        return
    logging.info('正在转换额外 Surge 规则...')
    for k, v in extra_surge_conf.items():
        source_file = os.path.join(current_dir, f'{k}.conf')
        response = requests.get(v, headers=headers)
        if response.status_code == 200:
            with open(source_file, 'wb') as f:
                f.write(response.content)
        else:
            logging.critical(f'{k}.conf 下载失败，状态码：{response.status_code}')
            exit(1)

        domain = []; domain_keyword = []; domain_suffix = []; ip_cidr = []; process_name = []

        with open(source_file, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip() or line.startswith('#'):
                    continue
                splits = line.strip().split(',')
                if len(splits) < 2:
                    continue
                rule_type, rule_content = splits[0], splits[1]
                if rule_type == 'DOMAIN':
                    domain.append(rule_content)
                elif rule_type == 'DOMAIN-SUFFIX':
                    domain_suffix.append(rule_content)
                elif rule_type == 'DOMAIN-KEYWORD':
                    domain_keyword.append(rule_content)
                elif rule_type in ('IP-CIDR', 'IP-CIDR6'):
                    ip_cidr.append(rule_content)
                elif rule_type == 'IP-ASN':
                    ip_cidr.extend(asn_v4[int(rule_content)])
                    ip_cidr.extend(asn_v6[int(rule_content)])
                elif rule_type == 'PROCESS-NAME':
                    process_name.append(rule_content)
                elif rule_type == 'USER-AGENT':
                    pass
                else:
                    logging.warning(f'未知规则类型：{rule_type}')

        sb_dir = os.path.join(SINGBOX_DIR, k)
        mh_dir = os.path.join(MIHOMO_DIR,  k)
        os.makedirs(sb_dir, exist_ok=True)
        os.makedirs(mh_dir, exist_ok=True)
        _write_singbox(k, sb_dir, domain, domain_keyword, domain_suffix, ip_cidr, process_name)
        _write_mihomo(k, mh_dir, domain, domain_keyword, domain_suffix, ip_cidr)
        _write_readme(k, sb_dir, mh_dir)


# ── 清理 ───────────────────────────────────────────────────────────────────

def post_clean():
    for path in [
        os.path.join(current_dir, 'asn'),
        os.path.join(current_dir, 'ios_rule_script'),
        os.path.join(current_dir, 'ljrgov_conf'),
    ]:
        if os.path.isdir(path):
            shutil.rmtree(path)
    for fname in ['ios_rule_script.zip', 'ljrgov_conf.zip']:
        fp = os.path.join(current_dir, fname)
        if os.path.exists(fp):
            os.remove(fp)
    # 保留 asn.zip 供 Actions cache 后步骤收集，Runner 结束后自动清理
    for key in extra_surge_conf:
        fp = os.path.join(current_dir, f'{key}.conf')
        if os.path.exists(fp):
            os.remove(fp)


# ── 入口 ───────────────────────────────────────────────────────────────────

def main():
    init()
    download_source_repo()
    download_ljrgov_repo()
    translate_rule()        # blackmatrix7 → singbox + mihomo
    translate_ljrgov()      # ljrgov/conf  → singbox + mihomo（与已有规则合并）
    translate_extra()       # 额外 Surge 规则
    post_clean()


if __name__ == '__main__':
    main()
