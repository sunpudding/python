<<<<<<< HEAD
# coding=utf-8
=======
# coding:utf-8
>>>>>>> 46f8484096f20838f553d72e356597e8d63536b3
from setuptools import setup

setup(name='analysispcap',
      version='0.1',
      description='对pcap文件进行解析，解析出tcp数据',
      url='https://github.com/sunpudding/python',
      author='sunpudding',
      author_email='463271945@qq.com',
      license='MIT',
      packages=['analysispcap'],
<<<<<<< HEAD
      include_package_data=True,
      zip_safe=False)
=======
      install_requires=[
          'struct',
            'argparse',

      ],
      test_suite='nose.collector',
      tests_require=['nose'],
      include_package_data=True,
      zip_safe=False)
>>>>>>> 46f8484096f20838f553d72e356597e8d63536b3
