# Implementation reference:
# https://developers.google.com/search/docs/appearance/ad-network-and-translation

import re
from urllib.parse import SplitResult, parse_qs, urlencode, urlsplit, urlunsplit


def decode_google_translate_hostname(parts: SplitResult, query_params: dict[str, list[str]]) -> str:
    domain_prefix = parts.hostname.split(".", 1)[0]

    encoding_list = query_params["_x_tr_enc"][0].split(",") if "_x_tr_enc" in query_params else []

    if "_x_tr_hp" in query_params and query_params["_x_tr_hp"]:
        domain_prefix = query_params["_x_tr_hp"][0] + domain_prefix

    # Remove leading "1-" when encoding includes "1"
    if "1" in encoding_list and domain_prefix.startswith("1-"):
        domain_prefix = domain_prefix[2:]

    # Remove leading "0-" when encoding includes "0", track IDN flag
    is_idn = False
    if "0" in encoding_list and domain_prefix.startswith("0-"):
        is_idn = True
        domain_prefix = domain_prefix[2:]

    # Replace single "-" with ".", then all double "--" with "-"
    decoded_segment = re.sub(r"\b-\b", ".", domain_prefix).replace("--", "-")

    # Add xn-- prefix for IDN
    if is_idn:
        decoded_segment = "xn--" + decoded_segment

    return decoded_segment


def decode(url: str) -> str:
    parts: SplitResult = urlsplit(url)
    query_params = parse_qs(parts.query)

    new_host = decode_google_translate_hostname(parts, query_params)
    if "@" in parts.netloc:
        user_info = parts.netloc.split("@")[0]
        new_netloc = f"{user_info}@{new_host}"
        if parts.port:
            new_netloc += f":{parts.port}"
    else:
        new_netloc = f"{new_host}:{parts.port}" if parts.port else new_host
    parts = parts._replace(netloc=new_netloc)

    if "_x_tr_sch" in query_params and query_params["_x_tr_sch"][0]:
        parts = parts._replace(scheme=query_params["_x_tr_sch"][0])

    for param in list(query_params.keys()):
        if param.startswith("_x_tr_"):
            del query_params[param]
    parts = parts._replace(query=urlencode(query_params, doseq=True))
    return urlunsplit(parts)
