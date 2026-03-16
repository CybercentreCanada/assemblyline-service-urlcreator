from urllib.parse import parse_qs, urlsplit

import pytest

from urlcreator.translate import decode, decode_google_translate_hostname


@pytest.mark.parametrize(
    "translate_url, redirect_url, redirect_domain",
    [
        ("https://www-rfc-editor-org.translate.goog/", "https://www.rfc.editor.org/", "www.rfc.editor.org"),
        ("https://www-rfc--editor-org.translate.goog/", "https://www.rfc-editor.org/", "www.rfc-editor.org"),
        ("https://www-rfc---editor-org.translate.goog/", "https://www.rfc--editor.org/", "www.rfc--editor.org"),
        ("https://www-rfc----editor-org.translate.goog/", "https://www.rfc--editor.org/", "www.rfc--editor.org"),
        ("https://www-rfc-----editor-org.translate.goog/", "https://www.rfc---editor.org/", "www.rfc---editor.org"),
        ("https://www-rfc------editor-org.translate.goog/", "https://www.rfc---editor.org/", "www.rfc---editor.org"),
        (
            "https://www-rfc-------editor-org.translate.goog/",
            "https://www.rfc----editor.org/",
            "www.rfc----editor.org",
        ),
        (
            "https://www-rfc--------editor-org.translate.goog/",
            "https://www.rfc----editor.org/",
            "www.rfc----editor.org",
        ),
    ],
)
def test_translate_dashes(translate_url, redirect_url, redirect_domain):
    assert decode(translate_url) == redirect_url
    parts = urlsplit(translate_url)
    query_params = parse_qs(parts.query)
    assert decode_google_translate_hostname(parts, query_params) == redirect_domain


def test_translate_scheme():
    translate_url = (
        "https://perdu-com.translate.goog/?_x_tr_sch=http&_x_tr_sl=fr&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp"
    )
    redirect_url = "http://perdu.com/"
    assert decode(translate_url) == redirect_url


def test_translate_with_fragment():
    translate_url = (
        "https://perdu-com.translate.goog/test?_x_tr_sl=fr&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp#fragment"
    )
    redirect_url = "https://perdu.com/test#fragment"
    assert decode(translate_url) == redirect_url


def test_translate_host_prefix():
    translate_url = "https://du-com.translate.goog/?_x_tr_hp=per"
    redirect_url = "https://perdu.com/"
    assert decode(translate_url) == redirect_url


@pytest.mark.parametrize(
    "translate_url, redirect_domain",
    [
        ("https://example-com.translate.goog", "example.com"),
        ("https://foo-example-com.translate.goog", "foo.example.com"),
        ("https://foo--example-com.translate.goog", "foo-example.com"),
        ("https://0-57hw060o-com.translate.goog/?_x_tr_enc=0", "xn--57hw060o.com"),
        ("https://1-en--us-example-com/?_x_tr_enc=1", "en-us.example.com"),
        ("https://0-en----w45as309w-com.translate.goog/?_x_tr_enc=0", "xn--en--w45as309w.com"),
        ("https://1-0-----16pw588q-com.translate.goog/?_x_tr_enc=0,1", "xn----16pw588q.com"),
        (
            "https://lanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch-co-uk.translate.goog/?_x_tr_hp=l",
            "llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk",
        ),
        (
            "https://lanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch-co-uk.translate.goog/?_x_tr_hp=www-l",
            "www.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk",
        ),
        (
            "https://a--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-com.translate.goog/?_x_tr_hp=a--xn--xn--xn--xn--xn--------------------------a",
            "a-xn-xn-xn-xn-xn-------------aa-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
        ),
        (
            "https://g5h3969ntadg44juhyah3c9aza87iiar4i410avdl8d3f1fuq3nz05dg5b-com.translate.goog/?_x_tr_enc=0&_x_tr_hp=0-",
            "xn--g5h3969ntadg44juhyah3c9aza87iiar4i410avdl8d3f1fuq3nz05dg5b.com",
        ),
    ],
)
def test_hostname(translate_url, redirect_domain):
    parts = urlsplit(translate_url)
    query_params = parse_qs(parts.query)
    assert decode_google_translate_hostname(parts, query_params) == redirect_domain
