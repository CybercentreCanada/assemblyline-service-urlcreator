from urlcreator.network import url_analysis as network_url_analysis


def url_analysis(url):
    return network_url_analysis(url, lambda qhash: None)


def test_unicode_characters():
    # Shouldn't crash due to non-ASCII characters being in the URL
    url = "https://hello:world@écoute.com/"
    res_section, network_iocs, behaviours = url_analysis(url)
    assert behaviours == {"embedded_credentials": {url}}
    assert network_iocs == {"uri": ["https://écoute.com/"], "domain": ["écoute.com"], "ip": []}
    assert res_section.tags == {
        "network.static.domain": ["écoute.com"],
        "network.static.uri": ["https://hello:world@écoute.com/", "https://écoute.com/"],
    }


def test_embedded_base64():
    url = "https://somedomain.com/some/path?u=a1aHR0cHM6Ly9iYWQuY29t#dGVzdEBleGFtcGxlLmNvbQ=="
    res_section, network_iocs, behaviours = url_analysis(url)
    assert behaviours == {}
    assert network_iocs == {"uri": ["https://bad.com"], "domain": ["bad.com"], "ip": []}
    assert res_section.tags == {
        # Encoded URL in query
        "network.static.uri": ["https://bad.com"],
        # Domain from encoded URL
        "network.static.domain": ["bad.com"],
        # Encoded email in fragment
        "network.email.address": ["test@example.com"],
    }

    # Handle garbage base64 strings, this shouldn't generate any results
    url = "https://somedomain.com/some/path?u=2F4wOWl6vSIfij9tBVr7MyOThiV1"
    res_section, network_iocs, behaviours = url_analysis(url)
    assert behaviours == {}
    assert network_iocs == {"uri": [], "domain": [], "ip": []}
    assert not res_section.body


def test_safelinks():
    # Ref: https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about?view=o365-worldwide
    url = "https://safelinks.com/?url=https%3A%2F%2Fhelloworld%2Ecom%2Fbad%7C01%7Ctest%40example%2Ecom"
    res_section, network_iocs, behaviours = url_analysis(url)
    assert behaviours == {}
    assert network_iocs == {
        # URL to be redirected to
        "uri": ["https://helloworld.com/bad"],
        "domain": ["helloworld.com"],
        "ip": [],
    }
    assert res_section.tags == {
        # URL to be redirected to
        "network.static.uri": ["https://helloworld.com/bad"],
        "network.static.domain": ["helloworld.com"],
        # Recipient email address
        "network.email.address": ["test@example.com"],
    }


def test_hexed_ip():
    # Ref: https://www.darkreading.com/cloud/shellbot-cracks-linux-ssh-servers-debuts-new-evasion-tactic
    url = "http://0x7f000001"
    res_section, network_iocs, behaviours = url_analysis(url)
    assert behaviours == {}
    assert network_iocs["ip"] == ["127.0.0.1"]
    assert res_section.tags == {"network.static.ip": ["127.0.0.1"]}


def test_phishing():
    # Ref: https://www.vmray.com/cyber-security-blog/detection-signature-updates-2/#elementor-toc__heading-anchor-9
    url = "https://google.com@wellsfargo.com@micrsoft.com@adobe.com@bad.com/malicious.zip?evil=true"
    res_section, network_iocs, behaviours = url_analysis(url)
    # Should reveal the true target URL for reputation checking
    assert behaviours == {"url_masquerade": {url}}
    assert network_iocs["uri"] == ["https://bad.com/malicious.zip?evil=true"]
    assert network_iocs["domain"] == ["bad.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://bad.com/malicious.zip?evil=true",
        ],
    }

    url = "https://username@adobe.com@bad.com/malicious.zip"
    res_section, network_iocs, behaviours = url_analysis(url)
    # Should reveal the true target URL for reputation checking
    assert behaviours == {"url_masquerade": {url}}
    assert network_iocs["uri"] == ["https://bad.com/malicious.zip"]
    assert network_iocs["domain"] == ["bad.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://bad.com/malicious.zip",
        ],
    }

    url = "https://adobe.com@bad.com/malicious.zip"
    res_section, network_iocs, behaviours = url_analysis(url)
    # Should reveal the true target URL for reputation checking
    assert behaviours == {"url_masquerade": {url}}
    assert network_iocs["uri"] == ["https://bad.com/malicious.zip"]
    assert network_iocs["domain"] == ["bad.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://bad.com/malicious.zip",
        ],
    }

    # Some samples are hiding the true domain further with spaces
    url = "https://adobe.com%20%20%20%20%20%20@bad.com/malicious.zip"
    res_section, network_iocs, behaviours = url_analysis(url)
    # Should reveal the true target URL for reputation checking
    assert behaviours == {"url_masquerade": {url}}
    assert network_iocs["uri"] == ["https://bad.com/malicious.zip"]
    assert network_iocs["domain"] == ["bad.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://bad.com/malicious.zip",
        ],
    }

    url = "https://something@not-a-url-with-tld@bad.com/malicious.zip"
    res_section, network_iocs, behaviours = url_analysis(url)
    # Should reveal the true target URL for reputation checking
    assert behaviours == {"embedded_username": {url}}
    assert network_iocs["uri"] == ["https://bad.com/malicious.zip"]
    assert network_iocs["domain"] == ["bad.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://bad.com/malicious.zip",
        ],
    }

    url = "https://username@bad.com/"
    res_section, network_iocs, behaviours = url_analysis(url)
    assert behaviours == {"embedded_username": {url}}
    assert network_iocs["uri"] == ["https://bad.com/"]
    assert network_iocs["domain"] == ["bad.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://bad.com/",
        ],
    }

    url = "https://username:password@bad.com/"
    res_section, network_iocs, behaviours = url_analysis(url)
    assert behaviours == {"embedded_credentials": {url}}
    assert network_iocs["uri"] == ["https://bad.com/"]
    assert network_iocs["domain"] == ["bad.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://bad.com/",
        ],
    }

    url = "https://123:xyz@example.com/"
    res_section, network_iocs, behaviours = url_analysis(url)
    assert behaviours == {"embedded_credentials": {url}}
    assert network_iocs["uri"] == ["https://example.com/"]
    assert network_iocs["domain"] == ["example.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://example.com/",
        ],
    }


def test_ascii_decode_handling():
    url = "https://site1.com/?url=http%3A%2F%2FData%25C2%25A0%3ASomething%40site2.com&data=other"
    res_section, network_iocs, behaviours = url_analysis(url)
    assert behaviours == {"embedded_credentials": {"http://Data%C2%A0:Something@site2.com"}}
    assert sorted(network_iocs["uri"]) == ["http://Data%C2%A0:Something@site2.com", "http://site2.com"]
    assert network_iocs["domain"] == ["site2.com"]
    assert '"OBFUSCATION": "encoding.url"' in res_section.body


def test_safelisted_domain():
    def lookup_safelist(qhash):
        safelist = {
            # safelistedenabled.com
            "ce8f92a43cfd33a74c190baa99947f5f28c2ac3845f0bac9506626c30a53615b": {"enabled": True},
            # safelisteddisabled.com
            "a3252645e0c7ddcba771ba349d091b4b16bed051786f51bf4751319d26f7aec8": {"enabled": False},
        }
        return safelist.get(qhash)

    url = "https://adobe.com@bad.com/malicious.zip"
    res_section, network_iocs, behaviours = network_url_analysis(url, lookup_safelist)
    # Should reveal the true target URL for reputation checking
    assert behaviours == {"url_masquerade": {url}}
    assert network_iocs["uri"] == ["https://bad.com/malicious.zip"]
    assert network_iocs["domain"] == ["bad.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://bad.com/malicious.zip",
        ],
    }

    url = "https://adobe.com@safelistedenabled.com/malicious.zip"
    res_section, network_iocs, behaviours = network_url_analysis(url, lookup_safelist)
    # Should reveal the true target URL for reputation checking
    assert behaviours == {"safelisted_url_masquerade": {url}}
    assert network_iocs["uri"] == ["https://safelistedenabled.com/malicious.zip"]
    assert network_iocs["domain"] == ["safelistedenabled.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://safelistedenabled.com/malicious.zip",
        ],
    }

    url = "https://adobe.com@safelisteddisabled.com/malicious.zip"
    res_section, network_iocs, behaviours = network_url_analysis(url, lookup_safelist)
    # Should reveal the true target URL for reputation checking
    assert behaviours == {"url_masquerade": {url}}
    assert network_iocs["uri"] == ["https://safelisteddisabled.com/malicious.zip"]
    assert network_iocs["domain"] == ["safelisteddisabled.com"]
    assert res_section.tags == {
        "network.static.uri": [
            url,
            "https://safelisteddisabled.com/malicious.zip",
        ],
    }
