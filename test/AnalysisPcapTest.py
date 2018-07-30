# -*- coding:utf-8 -*-
import unittest
# 导入AnalysisPcap.py
from TCP.PCAP.analysisPcap import *


class TestAnalysisPcap(unittest.TestCase):
    """Tests for AnalysisPcap"""

    def creat_new_analysispcap(self):
        """创建一个新的实例对象"""
        path1 = r'F:\photo\python\TCP\te2.pcap'
        path2 = r'F:\photo\python\TCP\http-content.txt'
        self.obj1 = AnalysisPcap(path1, path2)
        self.obj1.pcap_file_close()
        return self.obj1

    def open_pcap(self):
        """打开需要测试的pcpa文件"""
        pcap = r'F:\photo\python\TCP\te2.pcap'
        with open(pcap, 'rb') as fpcap:
            self.data = fpcap.read()
        return self.data

    def test_init_1(self):
        """测试初始化数据path1,path2"""
        path1 = r'F:\photo\python\TCP\te2.pcap'
        path2 = r'F:\photo\python\TCP\http-content.txt'
        obj2 = self.creat_new_analysispcap()
        result = False
        if obj2.path1 == path1 and obj2.path2 == path2:
            result = True
            return result
        self.assertTrue(result)

    def test_init_2(self):
        """测试初始化数据headerLen"""
        with open("black.pcap", "w") as f:
            pass
        path1 = r'black.pcap'
        path2 = r'http-blackcontent.txt'
        obj3 = AnalysisPcap(path1, path2)
        obj3.pcap_file_close()
        headerlen = 24
        self.assertEqual(obj3.headerLen, headerlen)

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
        pcap = r'F:\photo\python\TCP\te2.pcap'
        with open(pcap, 'rb') as f:
            data = f.read()
            header = [data[0:4], data[4:6], data[6:8],
                      data[8:12], data[12:16], data[16:20], data[20:24]]
        obj5 = self.creat_new_analysispcap().pcap_file_header()
        value = [v for k, v in obj5.items()]
        for i in range(0, 7):
            self.assertEqual(header[i], value[i])

    def test_packet_num(self):
        """"测试packet_num返回的数据包的数量"""
        data = self.open_pcap()
        obj6 = self.creat_new_analysispcap().packet_num()
        num = 0
        i = 24
        while i < len(data):
            lens = data[i + 12:i + 16]
            plen = struct.unpack('I', lens)[0]
            i = i + plen + 16
            num += 1
        self.assertEqual(num, obj6)

    def test_packet_len(self, gather=None):
        """测试packet_len返回的每个数据包的长度"""
        obj7 = self.creat_new_analysispcap().packet_len()
        data = self.open_pcap()
        i = 24
        if gather is None:
            gather = []
        while i < len(data):
            packetlen = struct.unpack(
                'I', data[i + 12:i + 16])[0]
            gather.append(packetlen)
            plen = struct.unpack('I', data[i + 12:i + 16])[0]
            i = i + plen + 16
        self.assertEqual(gather, obj7)
        pass

    def test_packet_ethernet_type(self, typegather=None):
        """测试packet_ethernet_type返回的以太网层type列表"""
        obj8 = self.creat_new_analysispcap().packet_ethernet_type()
        data = self.open_pcap()
        i = 24
        j = 0
        if typegather is None:
            typegather = []
        while i < len(data):
            per = hex(struct.unpack(
                '!H', self.data[i + 16 + 12:i + 16 + 14])[0])
            typegather.append(per)
            plen = struct.unpack('I', data[i + 12:i + 16])[0]
            i = i + int(plen) + 16
            j += 1
        self.assertEqual(typegather, obj8)
        pass

    def test_packet_ip_protocol(self, protocolgather=None):
        """测试packet_ip_protocol返回的ip层protocol列表"""
        obj9 = self.creat_new_analysispcap().packet_ip_protocol()
        data = self.open_pcap()
        i = 24
        if protocolgather is None:
            protocolgather = []
        j = 0
        while i < len(data):
            types = hex(struct.unpack(
                '!H', data[i + 16 + 12:i + 16 + 14])[0])
            if types == '0x800':
                per = hex(struct.unpack(
                    'b', data[i + 16 + 23:i + 16 + 24])[0])
                if per == '0x6':
                    protocolgather.append(per)
                else:
                    protocolgather.append('非TCP协议')
            else:
                protocolgather.append('此数据包不遵循IPV4协议')
            plen = struct.unpack('I', data[i + 12:i + 16])[0]
            i = i + int(plen) + 16
            j += 1
        self.assertEqual(protocolgather, obj9)

    def test_packet_ip_total_length(self, iplengather=None):
        """测试packet_ip_total_length返回的ip层totallength列表"""
        obj10 = self.creat_new_analysispcap().packet_ip_total_length()
        data = self.open_pcap()
        i = 24
        if iplengather is None:
            iplengather = []
        j = 0
        while i < len(data):
            types = hex(struct.unpack(
                '!H', data[i + 16 + 12:i + 16 + 14])[0])
            if types == '0x800':
                protocol = hex(struct.unpack(
                    'b', data[i + 16 + 23:i + 16 + 24])[0])
                if protocol == '0x6':
                    iplen = int(hex(struct.unpack(
                        '!H', data[i + 16 + 16:i + 16 + 18])[0]), 16)
                    iplengather.append(iplen)
                else:
                    iplengather.append('非TCP协议')
            else:
                iplengather.append('非TCP协议')
            plen = struct.unpack('I', data[i + 12:i + 16])[0]
            i = i + int(plen) + 16
            j += 1
        self.assertEqual(iplengather, obj10)

    def test_packet_ip_ihl(self, ihlgather=None):
        """测试packet_ip_ihl返回的ip层ihl列表"""
        obj11 = self.creat_new_analysispcap().packet_ip_ihl()
        data = self.open_pcap()
        i = 24
        if ihlgather is None:
            ihlgather = []
        j = 0
        while i < len(data):
            types = hex(struct.unpack(
                '!H', data[i + 16 + 12:i + 16 + 14])[0])
            if types == '0x800':
                protocol = hex(struct.unpack(
                    'b', data[i + 16 + 23:i + 16 + 24])[0])
                if protocol == '0x6':
                    ipheader = hex(struct.unpack(
                        'b', data[i + 16 + 14:i + 16 + 15])[0])
                    ipheaderlen = (int(ipheader, 16) & 0x0F) * 4
                    ihlgather.append(ipheaderlen)
                else:
                    ihlgather.append('非TCP协议')
            else:
                ihlgather.append('非TCP协议')
            plen = struct.unpack('I', data[i + 12:i + 16])[0]
            i = i + int(plen) + 16
            j += 1
        self.assertEqual(ihlgather, obj11)

    def test_packet_tcp_header_len(self, tcphgather=None):
        """测试packet_tcp_header_len返回的tcp报头长度列表"""
        obj12 = self.creat_new_analysispcap().packet_tcp_header_len()
        data = self.open_pcap()
        i = 24
        if tcphgather is None:
            tcphgather = []
        j = 0
        while i < len(data):
            types = hex(struct.unpack(
                '!H', data[i + 16 + 12:i + 16 + 14])[0])
            if types == '0x800':
                protocol = hex(struct.unpack(
                    'b', data[i + 16 + 23:i + 16 + 24])[0])
                if protocol == '0x6':
                    ipheader = hex(struct.unpack(
                        'b', data[i + 16 + 14:i + 16 + 15])[0])
                    ipheaderlen = (int(ipheader, 16) & 0x0F) * 4
                    tcphlen = hex(struct.unpack(
                        '!b',
                        data[i + 16 + 14 + ipheaderlen + 12:i + 16 + 14 + ipheaderlen + 13])[0])
                    tcpheaderlen = abs(int(tcphlen, 16) >> 4) * 4
                    tcphgather.append(tcpheaderlen)
                else:
                    tcphgather.append('非TCP协议')
            else:
                tcphgather.append('非TCP协议')
            plen = struct.unpack('I', data[i + 12:i + 16])[0]
            i = i + int(plen) + 16
            j += 1
        self.assertEqual(tcphgather, obj12)

    def test_packet_tcp_content(self, tcpcontentgather=None):
        """测试packet_tcp_content返回的tcp的应用层数据列表"""
        obj13 = self.creat_new_analysispcap().packet_tcp_content()
        data = self.open_pcap()
        i = 24
        if tcpcontentgather is None:
            tcpcontentgather = []
        j = 0
        while i < len(data):
            types = hex(struct.unpack(
                '!H', data[i + 16 + 12:i + 16 + 14])[0])
            if types == '0x800':
                protocol = hex(struct.unpack(
                    'b', data[i + 16 + 23:i + 16 + 24])[0])
                if protocol == '0x6':
                    iplen = int(hex(struct.unpack(
                        '!H', data[i + 16 + 16:i + 16 + 18])[0]), 16)
                    ipheader = hex(struct.unpack(
                        'b', data[i + 16 + 14:i + 16 + 15])[0])
                    ipheaderlen = (int(ipheader, 16) & 0x0F) * 4
                    tcphlen = hex(struct.unpack(
                        '!b',
                        data[i + 16 + 14 + ipheaderlen + 12:i + 16 + 14 + ipheaderlen + 13])[0])
                    tcpheaderlen = abs(int(tcphlen, 16) >> 4) * 4
                    tcpcontent = data[i +
                                      16 +
                                      14 +
                                      ipheaderlen +
                                      tcpheaderlen:i +
                                      16 +
                                      14 +
                                      iplen]
                    tcpcontentgather.append(tcpcontent)
                else:
                    tcpcontentgather.append('非IPV4协议下的TCP协议')
            else:
                tcpcontentgather.append('非IPV4协议下的TCP协议')
            plen = struct.unpack('I', data[i + 12:i + 16])[0]
            i = i + int(plen) + 16
            j += 1
        self.assertEqual(tcpcontentgather, obj13)

    def test_packet_tcpdata_1(self):
        """"测试写入本地的应用层数据文件"""
        obj14 = self.creat_new_analysispcap()
        tcpdata = obj14.packet_tcp_data()
        data = self.open_pcap()
        i = 24
        tcpcontentgather = []
        j = 0
        while i < len(data):
            types = hex(struct.unpack(
                '!H', data[i + 16 + 12:i + 16 + 14])[0])
            if types == '0x800':
                protocol = hex(struct.unpack(
                    'b', data[i + 16 + 23:i + 16 + 24])[0])
                if protocol == '0x6':
                    iplen = int(hex(struct.unpack(
                        '!H', data[i + 16 + 16:i + 16 + 18])[0]), 16)
                    ipheader = hex(struct.unpack(
                        'b', data[i + 16 + 14:i + 16 + 15])[0])
                    ipheaderlen = (int(ipheader, 16) & 0x0F) * 4
                    tcphlen = hex(struct.unpack(
                        '!b',
                        data[i + 16 + 14 + ipheaderlen + 12:i + 16 + 14 + ipheaderlen + 13])[0])
                    tcpheaderlen = abs(int(tcphlen, 16) >> 4) * 4
                    tcpcontent = data[i +
                                      16 +
                                      14 +
                                      ipheaderlen +
                                      tcpheaderlen:i +
                                      16 +
                                      14 +
                                      iplen]
                    if len(tcpcontent) == 0:
                        x = 'TCP的应用层数据:无' + '\n'
                        tcpcontentgather.append(x)
                    else:
                        x = 'TCP的应用层数据:%s' % tcpcontent + '\n'
                        tcpcontentgather.append(x)
                else:
                    tcpcontentgather.append('TCP的应用层数据:非IPV4协议下的TCP协议' + '\n')
            else:
                tcpcontentgather.append('TCP的应用层数据:非IPV4协议下的TCP协议' + '\n')
            plen = struct.unpack('I', data[i + 12:i + 16])[0]
            i = i + int(plen) + 16
            j += 1
        if self.assertEqual(len(tcpcontentgather), len(tcpdata)):
            for line in range(len(tcpcontentgather)):
                self.assertEqual(tcpcontentgather[line], tcpdata[line])

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()
