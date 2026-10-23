#!/usr/bin/env python3
import json
import os

from common import parse_singbox_json, SingBoxRuleSet
from mihomo import MIHOMO_DIR, write_mihomo_rule
from singbox import SINGBOX_DIR


def rebuild_rule(name: str) -> bool:
    sb_dir = os.path.join(SINGBOX_DIR, name)
    json_path = os.path.join(sb_dir, f'{name}.json')
    if not os.path.exists(json_path):
        return False

    with open(json_path, 'r', encoding='utf-8') as f:
        old_obj = json.load(f)

    data = parse_singbox_json(json_path)
    rebuilt = SingBoxRuleSet(*data)
    new_obj = {
        'version': rebuilt.version,
        'rules': rebuilt.rules,
    }

    changed = old_obj != new_obj
    if changed:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(new_obj, f, ensure_ascii=False, sort_keys=True, indent=2)
            f.write('\n')

    write_mihomo_rule(name, data)
    return changed


def main():
    changed = []
    for name in sorted(os.listdir(SINGBOX_DIR), key=str.lower):
        if not os.path.isdir(os.path.join(SINGBOX_DIR, name)):
            continue
        if rebuild_rule(name):
            changed.append(name)

    print(f'changed={len(changed)}')
    for name in changed:
        print(name)


if __name__ == '__main__':
    main()
