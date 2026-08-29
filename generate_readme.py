#!/usr/bin/env python3
"""
自动生成规则集总览 README.md。
在构建完成后运行，扫描 `rules/` 目录并根据生成状态输出总览文档。
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List
from urllib.parse import urlparse

from common import load_upstreams

REPO = 'milangree/rules'
RAW_BASE = f'https://raw.githubusercontent.com/{REPO}/main/rules'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SINGBOX_DIR = os.path.join(BASE_DIR, 'rules', 'singbox')
MIHOMO_DIR = os.path.join(BASE_DIR, 'rules', 'mihomo')


def count_rules(json_path: str):
    """解析 sing-box JSON，返回 (域名条数, IP 条数)。"""
    domain_count = 0
    ip_count = 0
    try:
        with open(json_path, encoding='utf-8') as f:
            data = json.load(f)
        for rule in data.get('rules', []):
            domain_count += (
                len(rule.get('domain', []))
                + len(rule.get('domain_suffix', []))
                + len(rule.get('domain_keyword', []))
            )
            ip_count += len(rule.get('ip_cidr', []))
    except Exception:
        pass
    return domain_count, ip_count


def icon_link(ok: bool, url: str, tooltip: str) -> str:
    """返回带链接的状态图标。"""
    icon = '✅' if ok else '❌'
    return f'[{icon}]({url} "{tooltip}")'


def format_count(value: int) -> str:
    return f'{value:,}' if value else '—'


def parse_github_repo(url: str) -> str:
    """从 GitHub 压缩包链接推导仓库首页地址。"""
    parsed = urlparse(url)
    if parsed.netloc.lower() != 'github.com':
        return url

    parts = [part for part in parsed.path.split('/') if part]
    if len(parts) >= 2:
        return f'https://github.com/{parts[0]}/{parts[1]}'
    return url


def humanize_upstream_name(upstream: Dict[str, str]) -> str:
    repo_url = parse_github_repo(upstream['url'])
    parsed = urlparse(repo_url)
    parts = [part for part in parsed.path.split('/') if part]
    if len(parts) >= 2:
        return f'{parts[0]}/{parts[1]}'
    return upstream.get('name', repo_url)


def load_upstream_descriptors() -> List[Dict[str, str]]:
    descriptors = []
    seen = set()
    for upstream in load_upstreams():
        repo_url = parse_github_repo(upstream['url'])
        name = humanize_upstream_name(upstream)
        key = (name, repo_url)
        if key in seen:
            continue
        seen.add(key)
        descriptors.append({
            'name': name,
            'url': repo_url,
            'type': upstream.get('type', 'unknown'),
        })
    return descriptors


def scan_rules() -> List[Dict[str, object]]:
    entries = []
    if not os.path.isdir(SINGBOX_DIR):
        return entries

    for name in sorted(os.listdir(SINGBOX_DIR), key=str.lower):
        sb_dir = os.path.join(SINGBOX_DIR, name)
        mh_dir = os.path.join(MIHOMO_DIR, name)
        if not os.path.isdir(sb_dir):
            continue

        json_path = os.path.join(sb_dir, f'{name}.json')
        srs_path = os.path.join(sb_dir, f'{name}.srs')
        d_yaml_path = os.path.join(mh_dir, f'{name}_domain.yaml')
        d_mrs_path = os.path.join(mh_dir, f'{name}_domain.mrs')
        c_yaml_path = os.path.join(mh_dir, f'{name}_classical.yaml')
        c_mrs_path = os.path.join(mh_dir, f'{name}_classical.mrs')
        i_yaml_path = os.path.join(mh_dir, f'{name}_ipcidr.yaml')
        i_mrs_path = os.path.join(mh_dir, f'{name}_ipcidr.mrs')

        if not os.path.exists(json_path):
            continue

        domain_count, ip_count = count_rules(json_path)
        has_domain = os.path.exists(d_yaml_path)
        has_classical = os.path.exists(c_yaml_path)
        has_ipcidr = os.path.exists(i_yaml_path)
        srs_ok = os.path.exists(srs_path)
        d_mrs_ok = os.path.exists(d_mrs_path)
        c_mrs_ok = os.path.exists(c_mrs_path)
        i_mrs_ok = os.path.exists(i_mrs_path)

        entries.append({
            'name': name,
            'domain_count': domain_count,
            'ip_count': ip_count,
            'total_count': domain_count + ip_count,
            'srs_ok': srs_ok,
            'has_domain': has_domain,
            'd_mrs_ok': d_mrs_ok,
            'has_classical': has_classical,
            'c_mrs_ok': c_mrs_ok,
            'has_ipcidr': has_ipcidr,
            'i_mrs_ok': i_mrs_ok,
            'srs_url': f'{RAW_BASE}/singbox/{name}/{name}.srs',
            'json_url': f'{RAW_BASE}/singbox/{name}/{name}.json',
            'd_mrs_url': f'{RAW_BASE}/mihomo/{name}/{name}_domain.mrs',
            'd_yaml_url': f'{RAW_BASE}/mihomo/{name}/{name}_domain.yaml',
            'c_mrs_url': f'{RAW_BASE}/mihomo/{name}/{name}_classical.mrs',
            'c_yaml_url': f'{RAW_BASE}/mihomo/{name}/{name}_classical.yaml',
            'i_mrs_url': f'{RAW_BASE}/mihomo/{name}/{name}_ipcidr.mrs',
            'i_yaml_url': f'{RAW_BASE}/mihomo/{name}/{name}_ipcidr.yaml',
        })

    return entries


def build_rule_rows(entries: List[Dict[str, object]]) -> str:
    rows = []
    for entry in entries:
        name = entry['name']

        sb_url = entry['srs_url'] if entry['srs_ok'] else entry['json_url']
        sb_tip = f'{name}.srs（二进制规则，可直接使用）' if entry['srs_ok'] else f'{name}.json（这个规则编译失败，已回退到源文件）'
        sb_cell = icon_link(entry['srs_ok'], sb_url, sb_tip)

        if entry['has_domain']:
            d_url = entry['d_mrs_url'] if entry['d_mrs_ok'] else entry['d_yaml_url']
            d_tip = f'{name}_domain.mrs（域名规则二进制）' if entry['d_mrs_ok'] else f'{name}_domain.yaml（域名规则编译失败，已回退到源文件）'
            d_cell = icon_link(entry['d_mrs_ok'], d_url, d_tip)
        else:
            d_cell = '—'

        if entry['has_classical']:
            c_url = entry['c_mrs_url'] if entry['c_mrs_ok'] else entry['c_yaml_url']
            c_tip = f'{name}_classical.mrs（Classical 规则二进制）' if entry['c_mrs_ok'] else f'{name}_classical.yaml（Classical 规则编译失败，已回退到源文件）'
            c_cell = icon_link(entry['c_mrs_ok'], c_url, c_tip)
        else:
            c_cell = '—'

        if entry['has_ipcidr']:
            i_url = entry['i_mrs_url'] if entry['i_mrs_ok'] else entry['i_yaml_url']
            i_tip = f'{name}_ipcidr.mrs（IP 规则二进制）' if entry['i_mrs_ok'] else f'{name}_ipcidr.yaml（IP 规则编译失败，已回退到源文件）'
            i_cell = icon_link(entry['i_mrs_ok'], i_url, i_tip)
        else:
            i_cell = '—'

        rows.append(
            f'| `{name}` | {sb_cell} | {d_cell} | {c_cell} | {i_cell} | '
            f'{format_count(entry["domain_count"])} | {format_count(entry["ip_count"])} | {format_count(entry["total_count"])} |'
        )

    return '\n'.join(rows)


def build_upstream_rows(upstreams: List[Dict[str, str]]) -> str:
    rows = []
    for upstream in upstreams:
        rows.append(
            f'| `{upstream["name"]}` | `{upstream["type"]}` | [{upstream["url"]}]({upstream["url"]}) |'
        )
    return '\n'.join(rows)


def generate(entries: List[Dict[str, object]], upstreams: List[Dict[str, str]]) -> str:
    tz8 = timezone(timedelta(hours=8))
    now = datetime.now(tz8)
    ts = now.strftime('%Y-%m-%d %H:%M:%S')
    date_badge = now.strftime('%Y.%m.%d')

    total = len(entries)
    total_domain = sum(entry['domain_count'] for entry in entries)
    total_ip = sum(entry['ip_count'] for entry in entries)
    total_rules = total_domain + total_ip
    total_upstreams = len(upstreams)

    srs_success = sum(1 for entry in entries if entry['srs_ok'])
    domain_success = sum(1 for entry in entries if entry['has_domain'] and entry['d_mrs_ok'])
    classical_success = sum(1 for entry in entries if entry['has_classical'] and entry['c_mrs_ok'])
    ip_success = sum(1 for entry in entries if entry['has_ipcidr'] and entry['i_mrs_ok'])
    domain_sets = sum(1 for entry in entries if entry['has_domain'])
    classical_sets = sum(1 for entry in entries if entry['has_classical'])
    ip_sets = sum(1 for entry in entries if entry['has_ipcidr'])

    rule_rows = build_rule_rows(entries)
    upstream_rows = build_upstream_rows(upstreams)

    return f"""# 📦 代理规则集

[![更新时间](https://img.shields.io/badge/更新时间-{date_badge}-blue?style=flat-square)](https://github.com/{REPO}/actions)
[![规则集数量](https://img.shields.io/badge/规则集-{total}个-brightgreen?style=flat-square)](https://github.com/{REPO})
[![规则总量](https://img.shields.io/badge/规则总量-{total_rules:,}条-orange?style=flat-square)](https://github.com/{REPO})
[![上游来源](https://img.shields.io/badge/上游-{total_upstreams}个-6f42c1?style=flat-square)](https://github.com/{REPO}/blob/main/upstreams.json)
[![sing-box](https://img.shields.io/badge/sing--box-支持-9b59b6?style=flat-square)](https://sing-box.sagernet.org)
[![mihomo](https://img.shields.io/badge/mihomo-支持-3498db?style=flat-square)](https://wiki.metacubex.one)

> 这里汇总的是每天自动生成的代理规则。
>
> 规则来自多个上游项目，统一整理后生成 sing-box 可用的 `.srs` 与 mihomo 可用的 `.mrs`。
>
> 作者：[milangree](https://github.com/milangree) · 许可证：GPL-3.0 · 本次构建：{ts}（UTC+8）

---

## ✨ 这个仓库做了什么

- 自动从 [`upstreams.json`](upstreams.json) 读取上游来源，文档内容和构建配置保持一致。
- 同一份规则会同时生成 sing-box 与 mihomo 两种格式，复制链接后即可直接使用。
- 如果某个二进制文件编译失败，会自动回退到源文件链接，方便继续下载和排查。
- README 会直接展示规则数量、生成状态和上游来源，不用自己翻日志。

## 📌 使用方式

### sing-box

```json
{{
  "type": "remote",
  "tag": "规则名称",
  "url": "{RAW_BASE}/singbox/规则名称/规则名称.srs",
  "format": "binary"
}}
```

> 远程规则地址使用 GitHub raw 链接。

### mihomo

```yaml
rule-providers:
  规则名称_domain:
    type: http
    behavior: domain
    format: mrs
    url: "{RAW_BASE}/mihomo/规则名称/规则名称_domain.mrs"
    interval: 86400
  规则名称_classical:
    type: http
    behavior: classical
    format: mrs
    url: "{RAW_BASE}/mihomo/规则名称/规则名称_classical.mrs"
    interval: 86400
  规则名称_ipcidr:
    type: http
    behavior: ipcidr
    format: mrs
    url: "{RAW_BASE}/mihomo/规则名称/规则名称_ipcidr.mrs"
    interval: 86400
```

> mihomo 规则同样使用 GitHub raw 链接。

---

## 📊 构建统计

| 项目 | 数量 |
|:-----|-----:|
| 上游项目数 | **{total_upstreams}** 个 |
| 规则集总数 | **{total}** 个 |
| 域名规则总量 | **{total_domain:,}** 条 |
| IP 规则总量 | **{total_ip:,}** 条 |
| 合计规则总量 | **{total_rules:,}** 条 |
| 构建时间 | {ts}（UTC+8） |

### ✅ 生成状态

> 看这一段就够了：数字相同代表全部编译成功；如果不相同，表格里的 ❌ 会自动回退到源文件链接。

| 类型 | 已生成 / 总数 |
|:-----|-------------:|
| sing-box `.srs` | **{srs_success} / {total}** |
| mihomo 域名 `.mrs` | **{domain_success} / {domain_sets}** |
| mihomo Classical `.mrs` | **{classical_success} / {classical_sets}** |
| mihomo IP `.mrs` | **{ip_success} / {ip_sets}** |

---

## 🔗 上游项目

| 名称 | 类型 | 地址 |
|:-----|:-----|:-----|
{upstream_rows}

---

## 📋 规则列表

> **图标说明**
> - ✅ 说明这个文件已经成功编译，点开就是可直接使用的生成文件
> - ❌ 说明这次编译没有通过，点开后会跳到源文件，方便临时使用或排查
> - `—` 说明这个规则集本身就没有这一类内容

<details>
<summary>📂 点击展开全部规则列表（共 {total} 个规则集 · {total_rules:,} 条规则）</summary>

<br>

| 规则名称 | sing&#8209;box `.srs` | mihomo 域名 `.mrs` | mihomo Classical `.mrs` | mihomo IP `.mrs` | 域名条数 | IP 条数 | 总条数 |
|:--------|:--------------------:|:-----------------:|:----------------------:|:---------------:|--------:|-------:|-------:|
{rule_rows}

</details>

---

## 🔗 相关链接

| 项目 | 地址 |
|:-----|:-----|
| sing-box 官方文档 | [sing-box.sagernet.org](https://sing-box.sagernet.org) |
| mihomo Wiki | [wiki.metacubex.one](https://wiki.metacubex.one) |
| GitHub Actions | [actions](https://github.com/{REPO}/actions) |

---

<sub>📝 本文件由 GitHub Actions 自动生成，请勿手动修改 · 最后更新：{ts}（UTC+8）</sub>
"""


def main():
    entries = scan_rules()
    upstreams = load_upstream_descriptors()

    if not entries:
        print('警告：未找到任何规则集，请确认 `rules/` 目录已正确生成', file=sys.stderr)

    content = generate(entries, upstreams)
    output = os.path.join(BASE_DIR, 'README.md')
    with open(output, 'w', encoding='utf-8') as f:
        f.write(content)

    print(
        'README 生成完成：'
        f'规则集 {len(entries)} 个，'
        f'上游 {len(upstreams)} 个，'
        f'输出文件 {output}'
    )


if __name__ == '__main__':
    main()
