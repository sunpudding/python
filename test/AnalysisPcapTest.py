# -*- coding:utf-8 -*-
import unittest
import os
# 导入AnalysisPcap.py
from analysispcap.analysisPcap import AnalysisPcap


class TestAnalysisPcap(unittest.TestCase):

    def creat_new_analysispcap(self):
        """创建一个新的实例对象"""
        currentposition = os.path.dirname(__file__)
        pcapath = os.path.split(currentposition)[0] + '/wireshark.pcap'
        path2 = os.path.split(currentposition)[0] + '/test/http-content.txt'
        self.obj1 = AnalysisPcap(pcapath, path2)
        self.obj1.pcap_file_close()
        return self.obj1

    def open_pcap(self):
        """打开需要测试的pcpa文件"""
        currentposition = os.path.dirname(__file__)
        pcap = os.path.split(currentposition)[0] + '/wireshark.pcap'
        with open(pcap, 'rb') as fpcap:
            self.data = fpcap.read()
        return self.data

    def test_init_1(self):
        """测试初始化数据pcappath,httpfile"""
        currentposition = os.path.dirname(__file__)
        path1 = os.path.split(currentposition)[0] + '/wireshark.pcap'
        path2 = os.path.split(currentposition)[0] + '/test/http-content.txt'
        obj2 = self.creat_new_analysispcap()
        result = False
        if obj2.pcapath == path1 and obj2.httpfile == path2:
            result = True
        self.assertTrue(result)

    def test_init_2(self):
        """测试初始化数据headerLen"""
        with open("black.pcap", "w") as f:
            pass
        path1 = r'black.pcap'
        path2 = r'http-blackcontent.txt'
        obj3 = AnalysisPcap(path1, path2)
        obj3.pcap_file_close()
        self.assertEqual(obj3.headerLen, 24)

    def test_pcap_file_header_1(self):
        """测试pcap_file_header创建的字典key"""

        obj4 = self.creat_new_analysispcap().pcap_file_header()
        header = [
            'magic_number',
            'version_major',
            'version_minor',
            'thiszone',
            'sigfigs',
            'snaplen',
            'linktype']
        key = [k for k, v in obj4.items()]
        for i in range(0, 7):
            self.assertEqual(header[i], key[i])

    def test_pcap_file_header_2(self):
        """测试pcap_file_header创建的字典value"""
        obj5 = self.creat_new_analysispcap().pcap_file_header()
        value = [v for k, v in obj5.items()]
        data = self.open_pcap()
        header = [data[0:4], data[4:6], data[6:8],
                  data[8:12], data[12:16], data[16:20], data[20:24]]
        for i in range(0, 7):
            self.assertEqual(header[i], value[i])

    def test_packet_num(self):
        """"测试packet_num返回的数据包的数量"""
        obj6 = self.creat_new_analysispcap().packet_num()
        self.assertEqual(3558, obj6)

    def test_packet_len(self):
        """测试packet_len返回的每个数据包的长度"""
        obj7 = self.creat_new_analysispcap().packet_len()
        per = False
        for i in obj7:
            if 0 < i <= 65535:
                per = True
        self.assertTrue(per)

    def test_packet_ethernet_type(self):
        """测试packet_ethernet_type返回的以太网层types的长度以及首位的两个字符"""
        obj8 = self.creat_new_analysispcap().packet_ethernet_type()
        for i in obj8:
            x = i[0:2]
            self.assertEqual(len(i), 5)
            self.assertEqual(x, '0x')

    def test_packet_ip_protocol(self):
        """测试packet_ip_protocol返回的ip层protocol列表"""
        obj9 = self.creat_new_analysispcap().packet_ip_protocol()
        self.assertEqual(set(obj9), {'0x6', '非TCP协议', '此数据包不遵循IPV4协议'})

    def test_packet_ip_total_length(self):
        """测试packet_ip_total_length返回的ip层totallength列表"""
        obj10 = self.creat_new_analysispcap().packet_ip_total_length()
        for i in obj10:
            if i == '非TCP协议':
                self.assertEqual(i, '非TCP协议')
            elif 20 <= i <= 65535:
                result = True
                self.assertTrue(result)

    def test_packet_ip_ihl(self):
        """测试packet_ip_ihl返回的ip层ihl列表"""
        obj11 = self.creat_new_analysispcap().packet_ip_ihl()
        for i in obj11:
            if i == '非TCP协议':
                self.assertEqual(i, '非TCP协议')
            elif 20 <= i <= 60:
                result = True
                self.assertTrue(result)

    def test_packet_tcp_header_len(self):
        """测试packet_tcp_header_len返回的tcp报头长度列表"""
        obj12 = self.creat_new_analysispcap().packet_tcp_header_len()
        for i in obj12:
            if i == '非TCP协议':
                self.assertEqual(i, '非TCP协议')
            elif 20 <= i <= 60:
                result = True
                self.assertTrue(result)

    def test_packet_tcp_content(self):
        """测试packet_tcp_content返回的tcp的应用层数据列表"""
        obj13 = self.creat_new_analysispcap().packet_tcp_content()
        self.assertEqual(obj13[0], b'')
        self.assertEqual(obj13[2], '非IPV4协议下的TCP协议')
        self.assertEqual(
            obj13[5],
            b'Y\x02\x00\x00\x01\x00\x01\x00\x94\x93p\xfb\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_packet_tcp_data(self):
        """"测试写入本地的应用层数据文件"""
        obj14 = self.creat_new_analysispcap().packet_tcp_data()
        self.assertEqual(obj14[0], 'TCP的应用层数据:无' + '\n')
        self.assertEqual(obj14[2], 'TCP的应用层数据:非IPV4协议下的TCP协议' + '\n')
        self.assertEqual(
            obj14[5],
            r"TCP的应用层数据:b'Y\x02\x00\x00\x01\x00\x01\x00\x94\x93p\xfb\x00\x00\x00\x00\x00\x00\x00\x00'" +
            "\n")

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()
