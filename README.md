# python #
## AnalysisPcap.py
* 在AnalysisPcapTest.py中，通过对pcap文件进行解析，分别将pcap文件头，tcp下的应用层http数据解析存为本地的txt文件中。
* 该tcp下的数据在存储在analysispcap/analysispcap/XX.txt

## test/AnalysisPcapTest.py
* 在test文件夹中的AnalysisPcapTest.py中,对AnalysisPcap.py进行单元测试
* 首先将analysispcap包通过pip install XX(analysispcap包在本地的绝对路径)或python setup.py install安装到python库中,方可直接运行AnalysisPcapTest.py
