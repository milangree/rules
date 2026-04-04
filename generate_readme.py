#!/usr/bin/env python3
"""
自动生成规则集总览 README.md
在 compile.sh 执行完成后运行，扫描 rules/ 目录判断编译状态。
"""

import os
import json
import sys
from datetime import datetime, timezone, timedelta

REPO     = 'milangree/rules'
RAW_BASE = f'https://raw.githubusercontent.com/{REPO}/main/rules'
CDN_BASE = f'https://cdn.jsdelivr.net/gh/{REPO}@main/rules'
UPSTREAM = 'https://github.com/blackmatrix7/ios_rule_script'

BASE_DIR    = os.getcwd()
SINGBOX_DIR = os.path.join(BASE_DIR, 'rules', 'singbox')
MIHOMO_DIR  = os.path.join(BASE_DIR, 'rules', 'mihomo')


# ── 工具函数 ────────────────────────────────────────────────────────────────

def count_rules(json_path: str):
    """解析 sing-box JSON，返回 (域名条数, IP 条数)"""
    domain_count = ip_count = 0
    try:
        with open(json_path, encoding='utf-8') as f:
            data = json.load(f)
        for rule in data.get('rules', []):
            domain_count += (
                len(rule.get('domain', [])) +
                len(rule.get('domain_suffix', [])) +
                len(rule.get('domain_keyword', []))
            )
            ip_count += len(rule.get('ip_cidr', []))
    except Exception:
        pass
    return domain_count, ip_count


def icon_link(ok: bool, url: str, tooltip: str) -> str:
    """✅ 成功（链接至编译文件）或 ❌ 失败（链接至源文件）"""
    icon = '✅' if ok else '❌'
    return f'[{icon}]({url} "{tooltip}")'


# ── 扫描规则集 ──────────────────────────────────────────────────────────────

def scan_rules() -> list:
    entries = []
    if not os.path.isdir(SINGBOX_DIR):
        return entries

    for name in sorted(os.listdir(SINGBOX_DIR)):
        sb_dir = os.path.join(SINGBOX_DIR, name)
        mh_dir = os.path.join(MIHOMO_DIR,  name)
        if not os.path.isdir(sb_dir):
            continue

        # 文件路径
        json_path   = os.path.join(sb_dir, f'{name}.json')
        srs_path    = os.path.join(sb_dir, f'{name}.srs')
        d_yaml_path = os.path.join(mh_dir, f'{name}_domain.yaml')
        d_mrs_path  = os.path.join(mh_dir, f'{name}_domain.mrs')
        i_yaml_path = os.path.join(mh_dir, f'{name}_ipcidr.yaml')
        i_mrs_path  = os.path.join(mh_dir, f'{name}_ipcidr.mrs')

        domain_count, ip_count = count_rules(json_path)

        entries.append({
            'name':         name,
            'domain_count': domain_count,
            'ip_count':     ip_count,
            # sing-box
            'srs_ok':       os.path.exists(srs_path),
            'srs_url':      f'{RAW_BASE}/singbox/{name}/{name}.srs',
            'json_url':     f'{RAW_BASE}/singbox/{name}/{name}.json',
            # mihomo domain
            'has_domain':   os.path.exists(d_yaml_path),
            'd_mrs_ok':     os.path.exists(d_mrs_path),
            'd_mrs_url':    f'{RAW_BASE}/mihomo/{name}/{name}_domain.mrs',
            'd_yaml_url':   f'{RAW_BASE}/mihomo/{name}/{name}_domain.yaml',
            # mihomo ipcidr
            'has_ipcidr':   os.path.exists(i_yaml_path),
            'i_mrs_ok':     os.path.exists(i_mrs_path),
            'i_mrs_url':    f'{RAW_BASE}/mihomo/{name}/{name}_ipcidr.mrs',
            'i_yaml_url':   f'{RAW_BASE}/mihomo/{name}/{name}_ipcidr.yaml',
        })

    return entries


# ── README 生成 ─────────────────────────────────────────────────────────────

def generate(entries: list) -> str:
    tz8 = timezone(timedelta(hours=8))
    now  = datetime.now(tz8)
    ts   = now.strftime('%Y-%m-%d %H:%M:%S')
    # shields.io badge 中 '-' 用 '--' 转义，空格用 '_'
    date_badge = now.strftime('%Y.%m.%d')

    total        = len(entries)
    total_domain = sum(e['domain_count'] for e in entries)
    total_ip     = sum(e['ip_count']     for e in entries)
    total_rules  = total_domain + total_ip

    # ── 规则表格 ────────────────────────────────────────────────────────────
    rows = []
    for e in entries:
        n = e['name']

        # sing-box 列
        sb_url  = e['srs_url']  if e['srs_ok']   else e['json_url']
        sb_tip  = f"{n}.srs"    if e['srs_ok']   else f"{n}.json（编译失败，已回退）"
        sb_cell = icon_link(e['srs_ok'], sb_url, sb_tip)

        # mihomo 域名列
        if e['has_domain']:
            d_url  = e['d_mrs_url']  if e['d_mrs_ok'] else e['d_yaml_url']
            d_tip  = f"{n}_domain.mrs" if e['d_mrs_ok'] else f"{n}_domain.yaml（编译失败，已回退）"
            d_cell = icon_link(e['d_mrs_ok'], d_url, d_tip)
        else:
            d_cell = '—'

        # mihomo IP 列
        if e['has_ipcidr']:
            i_url  = e['i_mrs_url']  if e['i_mrs_ok'] else e['i_yaml_url']
            i_tip  = f"{n}_ipcidr.mrs" if e['i_mrs_ok'] else f"{n}_ipcidr.yaml（编译失败，已回退）"
            i_cell = icon_link(e['i_mrs_ok'], i_url, i_tip)
        else:
            i_cell = '—'

        d_str = f'{e["domain_count"]:,}' if e['domain_count'] else '—'
        i_str = f'{e["ip_count"]:,}'     if e['ip_count']     else '—'

        rows.append(
            f'| `{n}` | {sb_cell} | {d_cell} | {i_cell} | {d_str} | {i_str} |'
        )

    table = '\n'.join(rows)

    # ── 完整 README ─────────────────────────────────────────────────────────
    return f"""\
# 📦 代理规则集

[![更新时间](https://img.shields.io/badge/更新时间-{date_badge}-blue?style=flat-square)](https://github.com/{REPO}/actions)
[![规则集数量](https://img.shields.io/badge/规则集-{total}个-brightgreen?style=flat-square)](https://github.com/{REPO})
[![规则总量](https://img.shields.io/badge/规则总量-{total_rules:,}条-orange?style=flat-square)](https://github.com/{REPO})
[![sing-box](https://img.shields.io/badge/sing--box-支持-9b59b6?style=flat-square)](https://sing-box.sagernet.org)
[![mihomo](https://img.shields.io/badge/mihomo-支持-3498db?style=flat-square)](https://wiki.metacubex.one)

> 每日自动构建，基于上游项目 [blackmatrix7/ios_rule_script]({UPSTREAM}) 的 Clash 规则，
> 经 GitHub Actions 自动编译为 sing-box `.srs` 与 mihomo `.mrs` 二进制格式后发布。
>
> 作者：[milangree](https://github.com/milangree) · 许可证：GPL-3.0 · 本次构建：{ts}（UTC+8）

---

## 📌 使用方式

### sing-box

在规则集配置中填写对应规则的 `.srs` 链接：

```json
{{
  "type": "remote",
  "tag": "规则名称",
  "url": "{RAW_BASE}/singbox/规则名称/规则名称.srs",
  "format": "binary"
}}
```

> 国内可使用 jsDelivr CDN 加速访问：
> `{CDN_BASE}/singbox/规则名称/规则名称.srs`

### mihomo

域名规则（`domain`）与 IP 规则（`ipcidr`）需分开引用：

```yaml
rule-providers:
  规则名称_domain:
    type: http
    behavior: domain
    format: mrs
    url: "{RAW_BASE}/mihomo/规则名称/规则名称_domain.mrs"
    interval: 86400
  规则名称_ipcidr:
    type: http
    behavior: ipcidr
    format: mrs
    url: "{RAW_BASE}/mihomo/规则名称/规则名称_ipcidr.mrs"
    interval: 86400
```

---

## 📊 本次构建统计

| 项目 | 数量 |
|:-----|-----:|
| 规则集总数 | **{total}** 个 |
| 域名规则总量 | **{total_domain:,}** 条 |
| IP 规则总量 | **{total_ip:,}** 条 |
| 合计规则总量 | **{total_rules:,}** 条 |
| 构建时间 | {ts}（UTC+8） |
| 上游来源 | [blackmatrix7/ios_rule_script]({UPSTREAM}) |

---

## 📋 规则列表

> **图标说明**
> - ✅ 编译成功，点击图标可跳转至对应文件（右键 → 复制链接地址，即可获取完整 URL）
> - ❌ 编译失败，已自动回退至源文件（`.json` / `.yaml`）
> - `—` 该规则集不包含此类规则（例如纯域名规则集无 IP 列）

<details>
<summary>📂 点击展开全部规则列表（共 {total} 个规则集 · {total_rules:,} 条规则）</summary>

<br>

| 规则名称 | sing&#8209;box `.srs` | mihomo 域名 `.mrs` | mihomo IP `.mrs` | 域名条数 | IP 条数 |
|:--------|:--------------------:|:-----------------:|:---------------:|--------:|-------:|
{table}

</details>

---

## 🔗 相关链接

| 项目 | 地址 |
|:-----|:-----|
| 上游规则来源 | [blackmatrix7/ios_rule_script]({UPSTREAM}) |
| sing-box 官方文档 | [sing-box.sagernet.org](https://sing-box.sagernet.org) |
| mihomo Wiki | [wiki.metacubex.one](https://wiki.metacubex.one) |
| jsDelivr CDN | [jsdelivr.com](https://www.jsdelivr.com) |

---

<sub>📝 本文件由 GitHub Actions 自动生成，请勿手动修改 · 最后更新：{ts}（UTC+8）</sub>
"""


# ── 入口 ────────────────────────────────────────────────────────────────────

def main():
    entries = scan_rules()
    if not entries:
        print('⚠️  警告：未找到任何规则集，请确认 rules/ 目录已正确生成', file=sys.stderr)
    content = generate(entries)
    output  = os.path.join(BASE_DIR, 'README.md')
    with open(output, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'✅ README.md 生成完成，共收录 {len(entries)} 个规则集')


if __name__ == '__main__':
    main()
