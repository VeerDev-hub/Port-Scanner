from validators import extract_domain, parse_port_targets


def test_extract_domain_keeps_cidr():
    assert extract_domain("192.168.1.0/24") == "192.168.1.0/24"


def test_extract_domain_from_url():
    assert extract_domain("https://example.com/path") == "example.com"


def test_parse_port_targets_range():
    ports, text = parse_port_targets("22,80,443", 100)
    assert ports == [22, 80, 443]
    assert text == "22,80,443"


def test_parse_port_targets_count_fallback():
    ports, text = parse_port_targets("", 5)
    assert ports == [1, 2, 3, 4, 5]
    assert text == "1-5"
