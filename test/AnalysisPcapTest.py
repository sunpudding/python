# -*- coding: UTF-8 -*-
from analysispcap import AnalysisPcap
import binascii

def test_is_ipv4_tcp():
    """测试数据帧是否为IPV4协议"""
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    example = AnalysisPcap(pcap_file, http_file)
    data_true = binascii.a2b_hex(
        '2054fa2ad244c821589685a7080045000028688e40008006d291c0a82b9e6f0d645cfb3c01bbcad54c3d86f5ccf15011040084310000')
    data_false = binascii.a2b_hex(
        '2054fa2ad244c821589685a708060001080006040001c821589685a7c0a82b9e2054fa2ad244c0a82b01')
    assert example.is_ipv4_tcp(data_true)
    assert example.is_ipv4_tcp(data_false) is False


def test_dump_tcp_content():
    """ 测试dump_tcp_content返回的列表中的content内容"""
    http_file, pcap_file = 'single-http.txt', 'single-frame.pcap'
    http_file1, pcap_file1 = 'http.txt', 'sinatcp.pcap'
    obj = AnalysisPcap(pcap_file, http_file)
    tcp_content = obj.dump_tcp_content()
    assert tcp_content[0][7] == binascii.a2b_hex('5902000001000100949370fb0000000000000000')
    example = AnalysisPcap(pcap_file1, http_file1)
    data1 = example.dump_tcp_content()
    assert data1[0][7] == b''
    assert data1[4][7] == binascii.a2b_hex('5902000001000100949370fb0000000000000000')


def test_get_tcp_data():
    """测试获取的tcpdata列表[src, dst,src_port,dst_port, seq, ack, flags, content]"""
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    example = AnalysisPcap(pcap_file, http_file)
    data_true = binascii.a2b_hex(
        '2054fa2ad244c821589685a708004500003c469240008006e605c0a82b9eca6c1771d8570050db1569575186d1415018004140e500005902000001000100949370fb0000000000000000')
    content = binascii.a2b_hex('5902000001000100949370fb0000000000000000')
    assert example.get_tcp_data(data_true) == ['192.168.43.158','202.108.23.113',55383,80,3675613527,1367789889,24,content]

def test_dump_reassemble_stream():
    """测试指定重组流中的数据"""
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    client = ['192.168.43.158', 64343]
    server = ['183.232.24.222', 80]
    example = AnalysisPcap(pcap_file, http_file).dump_reassemble_stream(client, server)
    assert example[3][:7] == ['183.232.24.222', '192.168.43.158', 80, 64343, 3158707696, 2465438596, 24]
    assert len(example[3][7]) == 472
    assert example[3][8] == 'S->C'

def test_write_file():
    """"测试写入本地的应用层数据文件"""
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    creat_http_file = AnalysisPcap(pcap_file, http_file).write_file()
    read_line = open(http_file, 'r', encoding='utf-8').readlines()
    data_true = binascii.a2b_hex('5902000001000100949370fb0000000000000000')
    data_false = binascii.a2b_hex(
        '000001000100949370fb000000000000000059020000')
    last_data = binascii.a2b_hex(
        '00')
    assert read_line[0] == 'TCP的应用层数据:{}\n'.format(data_true)
    assert read_line[1] != 'TCP的应用层数据:{}\n'.format(data_true)
    assert read_line[0] != 'TCP的应用层数据:{}\n'.format(data_false)
    assert read_line[-1] == 'TCP的应用层数据:{}\n'.format(last_data)
