#!/bin/bash
set -Eeuo pipefail

# ── sing-box：编译 .json → .srs ────────────────────────────────────────────
echo "====== 开始编译 sing-box 规则集 ======"
sb_ok=0; sb_fail=0
singbox_base="rules/singbox"

for dir in "$singbox_base"/*/; do
    name=$(basename "$dir")
    json_file="$dir/$name.json"
    if [[ -f "$json_file" ]]; then
        srs_file="$dir/$name.srs"
        if sing-box rule-set compile --output "$srs_file" "$json_file" 2>/dev/null; then
            echo "  ✓  [singbox] $name"
            ((sb_ok++)) || true
        else
            echo "  ✗  [singbox] $name（编译失败）"
            ((sb_fail++)) || true
        fi
    else
        echo "  -  [singbox] $name（json 不存在，跳过）"
    fi
done

echo "sing-box 完成：成功 $sb_ok 个，失败 $sb_fail 个"
echo ""

# ── mihomo：编译 _domain.yaml / _ipcidr.yaml → .mrs ────────────────────────
echo "====== 开始编译 mihomo 规则集 ======"
mh_ok=0; mh_fail=0
mihomo_base="rules/mihomo"

for dir in "$mihomo_base"/*/; do
    name=$(basename "$dir")

    d_yaml="$dir/${name}_domain.yaml"
    if [[ -f "$d_yaml" ]]; then
        d_mrs="$dir/${name}_domain.mrs"
        if mihomo convert-ruleset domain yaml "$d_yaml" "$d_mrs" 2>/dev/null; then
            echo "  ✓  [mihomo/domain]  $name"
            ((mh_ok++)) || true
        else
            echo "  ✗  [mihomo/domain]  $name（编译失败）"
            ((mh_fail++)) || true
        fi
    fi

    i_yaml="$dir/${name}_ipcidr.yaml"
    if [[ -f "$i_yaml" ]]; then
        i_mrs="$dir/${name}_ipcidr.mrs"
        if mihomo convert-ruleset ipcidr yaml "$i_yaml" "$i_mrs" 2>/dev/null; then
            echo "  ✓  [mihomo/ipcidr]  $name"
            ((mh_ok++)) || true
        else
            echo "  ✗  [mihomo/ipcidr]  $name（编译失败）"
            ((mh_fail++)) || true
        fi
    fi
done

echo "mihomo 完成：成功 $mh_ok 个，失败 $mh_fail 个"
echo ""
echo "====== 全部编译任务完成 ======"
