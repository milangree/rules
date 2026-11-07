#!/usr/bin/env python3
import subprocess
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    logging.info('开始构建 sing-box 规则集...')
    subprocess.run([sys.executable, 'singbox.py'], check=True)
    logging.info('开始构建 mihomo 规则集...')
    subprocess.run([sys.executable, 'mihomo.py'], check=True)
    logging.info('全部构建完成！')

if __name__ == '__main__':
    main()
