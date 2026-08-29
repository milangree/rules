#!/usr/bin/env python3
import os
import tempfile
import unittest
from unittest.mock import patch

from common import iter_rules, parse_clash_yaml
import mihomo


class MihomoRuleCompatibilityTests(unittest.TestCase):
    def write_file(self, path: str, content: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    def test_parse_domain_behavior_wildcards_preserved(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = os.path.join(tmpdir, 'wildcards.yaml')
            self.write_file(
                yaml_path,
                """payload:
  - '.blogger.com'
  - '*.*.microsoft.com'
  - 'books.itunes.apple.com'
  - '+.xboxlive.com'
""",
            )

            data = parse_clash_yaml(yaml_path)
            domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical = data

            self.assertEqual(domain, ['books.itunes.apple.com'])
            self.assertEqual(domain_keyword, [])
            self.assertEqual(domain_suffix, ['xboxlive.com'])
            self.assertEqual(domain_regex, [])
            self.assertEqual(ip_cidr, [])
            self.assertEqual(process_name, [])
            self.assertEqual(domain_wildcard, ['.blogger.com', '*.*.microsoft.com'])
            self.assertEqual(classical, [])

    def test_iter_rules_merges_domain_and_classical_variants(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_dir = os.path.join(tmpdir, 'Sample')
            self.write_file(
                os.path.join(rule_dir, 'Sample.yaml'),
                """payload:
  - '.blogger.com'
  - '+.xboxlive.com'
""",
            )
            self.write_file(
                os.path.join(rule_dir, 'Sample_Classical.yaml'),
                """payload:
  - DOMAIN,ad.com
  - PROCESS-NAME,ExampleApp.exe
  - SRC-IP-CIDR,192.168.1.201/32
""",
            )

            items = list(iter_rules({'type': 'clash'}, tmpdir))
            self.assertEqual(len(items), 1)
            name, data = items[0]
            self.assertEqual(name, 'Sample')

            domain, domain_keyword, domain_suffix, domain_regex, ip_cidr, process_name, domain_wildcard, classical = data
            self.assertEqual(domain, ['ad.com'])
            self.assertEqual(domain_keyword, [])
            self.assertEqual(domain_suffix, ['xboxlive.com'])
            self.assertEqual(domain_regex, [])
            self.assertEqual(ip_cidr, [])
            self.assertEqual(process_name, ['ExampleApp.exe'])
            self.assertEqual(domain_wildcard, ['.blogger.com'])
            self.assertEqual(classical, ['DOMAIN,ad.com', 'PROCESS-NAME,ExampleApp.exe', 'SRC-IP-CIDR,192.168.1.201/32'])

    def test_write_mihomo_rule_emits_domain_classical_and_ip_sets(self):
        data = (
            ['books.itunes.apple.com'],
            [],
            ['xboxlive.com'],
            [],
            ['1.1.1.0/24'],
            ['ExampleApp.exe'],
            ['.blogger.com', '*.*.microsoft.com'],
            ['DOMAIN,*.baidu.com', 'PROCESS-NAME,ExampleApp.exe'],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(mihomo, 'MIHOMO_DIR', tmpdir):
                mihomo.write_mihomo_rule('Sample', data)

            rule_dir = os.path.join(tmpdir, 'Sample')
            with open(os.path.join(rule_dir, 'Sample_domain.yaml'), encoding='utf-8') as f:
                domain_yaml = f.read()
            with open(os.path.join(rule_dir, 'Sample_classical.yaml'), encoding='utf-8') as f:
                classical_yaml = f.read()
            with open(os.path.join(rule_dir, 'Sample_ipcidr.yaml'), encoding='utf-8') as f:
                ip_yaml = f.read()
            with open(os.path.join(rule_dir, 'README.md'), encoding='utf-8') as f:
                readme = f.read()

            self.assertIn('  - books.itunes.apple.com\n', domain_yaml)
            self.assertIn('  - +.xboxlive.com\n', domain_yaml)
            self.assertIn('  - .blogger.com\n', domain_yaml)
            self.assertIn('  - *.*.microsoft.com\n', domain_yaml)

            self.assertIn('  - DOMAIN,*.baidu.com\n', classical_yaml)
            self.assertIn('  - PROCESS-NAME,ExampleApp.exe\n', classical_yaml)
            self.assertIn('  - DOMAIN,books.itunes.apple.com\n', classical_yaml)
            self.assertIn('  - DOMAIN-SUFFIX,xboxlive.com\n', classical_yaml)

            self.assertIn('  - 1.1.1.0/24\n', ip_yaml)
            self.assertIn('Sample_classical.mrs', readme)
            self.assertIn('Sample_classical.yaml', readme)


if __name__ == '__main__':
    unittest.main()
