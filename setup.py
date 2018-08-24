# -*- coding:utf-8 -*-
from setuptools import setup

setup(name='analysispcap',
      version='0.3',
      description='Analysispcap对pcap文件进行解析，解析出tcp数据;Peer返回address列表，TcpData用于重组tcpdtream',
      url='https://github.com/sunpudding/python',
      author='sunpudding',
      author_email='463271945@qq.com',
      license='MIT',
      packages=['analysispcap'],
      include_package_data=True,
      zip_safe=False)
