from analysispcap.analysisPcap import AnalysisPcap
import binascii


def test_dump_tcp_content():
    """ 测试dump_tcp_content返回的列表中的数据帧"""
    obj = AnalysisPcap('single-frame.pcap', 'http.txt')
    tcp_content = obj.dump_tcp_content()
    tcp_data = binascii.a2b_hex('5902000001000100949370fb0000000000000000')
    assert tcp_content == [tcp_data]
    example = AnalysisPcap('sinatcp.pcap', 'http.txt')
    data1 = example.dump_tcp_content()
    assert data1[5] == tcp_data
    assert data1[6] != tcp_data


def test_is_ipv4():
    """测试数据帧是否为IPV4协议"""
    example = AnalysisPcap('sinatcp.pcap', 'http.txt')
    data_true = binascii.a2b_hex(
        '2054fa2ad244c821589685a7080045000028688e40008006d291c0a82b9e6f0d645cfb3c01bbcad54c3d86f5ccf15011040084310000')
    data_false = binascii.a2b_hex(
        '2054fa2ad244c821589685a708060001080006040001c821589685a7c0a82b9e2054fa2ad244c0a82b01')
    assert example.is_ipv4(data_true)
    assert example.is_ipv4(data_false) is False


def test_is_tcp():
    """测试数据帧是否为tcp协议"""
    example = AnalysisPcap('sinatcp.pcap', 'http.txt')
    tcp_true = binascii.a2b_hex(
        '2054fa2ad244c821589685a7080045000028688e40008006d291c0a82b9e6f0d645cfb3c01bbcad54c3d86f5ccf15011040084310000')
    tcp_false = binascii.a2b_hex(
        'c821589685a72054fa2ad24408004504006b59a940003411f22e6f1e9f41c0a82b9e1f400fbb0057dc3c02373f0081b17a1b9cf80900000006c25ae346c20de45234640b44883b443a745f3a5f276b1b628e97b2284697d8c70c47febe30cf04328ad9f4f17aa5863db8f279640ad82afd1bc372cca5cf5e03')
    assert example.is_tcp(tcp_true)
    assert example.is_tcp(tcp_false) is False


def test_get_tcp_data():
    """"测试从数据帧中获取的tcp中的数据"""
    example = AnalysisPcap('sinatcp.pcap', 'http.txt')
    tcpdata_true = binascii.a2b_hex(
        '2054fa2ad244c821589685a708004500003c469240008006e605c0a82b9eca6c1771d8570050db1569575186d1415018004140e500005902000001000100949370fb0000000000000000')
    tcpdata_empty = binascii.a2b_hex(
        '2054fa2ad244c821589685a7080045000028688e40008006d291c0a82b9e6f0d645cfb3c01bbcad54c3d86f5ccf15011040084310000')
    assert example.get_tcp_data(tcpdata_true) == binascii.a2b_hex(
        '5902000001000100949370fb0000000000000000')
    assert example.get_tcp_data(tcpdata_true) != binascii.a2b_hex(
        '503231000100949370fb00000000')
    assert example.get_tcp_data(tcpdata_empty) == b''
    assert example.get_tcp_data(tcpdata_empty) != binascii.a2b_hex(
        '503231000100949370fb00000000')


def test_packet_tcp_data():
    """"测试写入本地的应用层数据文件"""
    example = AnalysisPcap('sinatcp.pcap', 'http.txt')
    newexample = AnalysisPcap('sinatcp.pcap', 'http.txt')
    data_true = binascii.a2b_hex('5902000001000100949370fb0000000000000000')
    data_false = binascii.a2b_hex(
        '000001000100949370fb000000000000000059020000')
    assert example.write_file()[0] == "TCP的应用层数据:%s" % data_true + '\n'
    assert newexample.write_file()[0] != "TCP的应用层数据:%s" % data_false + '\n'
