import binascii
import hashlib
import re
from base64 import b64decode
from collections import defaultdict
from typing import Callable, Dict, List, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline_v4_service.common.result import (
    ResultSection,
    ResultTableSection,
    TableRow,
)
from multidecoder.decoders.base64 import BASE64_RE
from multidecoder.decoders.network import (
    DOMAIN_TYPE,
    EMAIL_TYPE,
    IP_TYPE,
    URL_TYPE,
    parse_url,
)
from multidecoder.multidecoder import Multidecoder
from multidecoder.node import Node
from multidecoder.registry import get_analyzers
from multidecoder.string_helper import make_bytes, make_str

from urlcreator.proofpoint import URLDefenseDecoder

NETWORK_IOC_TYPES = ["domain", "ip", "uri"]
BEHAVIOUR_SCORES = {
    "safelisted_url_masquerade": 0,
    "url_masquerade": 500,
    "embedded_credentials": 0,
    "embedded_username": 0,
}
URLDEFENSEDECODER = URLDefenseDecoder()


def manual_base64_decode(parent_node, md):
    for b64_match in re.finditer(BASE64_RE, parent_node.value):
        # htt → base64 → aHR0
        b64_string = b64_match.group()
        if b"aHR0" in b64_string:
            b64_string = b64_string[b64_string.index(b"aHR0") :]
            remaining_characters = len(b64_string) % 4

            # Perfect base64 length
            if not remaining_characters:
                pass
            # Imperfect length, adding padding is required if there's at most 2 characters missing
            elif remaining_characters >= 2:
                b64_string += b"=" * (4 - remaining_characters)
            # Imperfect length and padding with 3 "=" doesn't make sense, start removing characters
            else:
                b64_string = b64_string[:-1]

            scan_result = md.scan(b64_string)

            if scan_result.children:
                for child in scan_result.children:
                    yield child
            else:
                try:
                    # Attempt decoding manually
                    scan_result = md.scan(b64decode(b64_string)).children[0]
                    # Manipulate the result to preserve the encoded → decoded process
                    scan_result.end = 0
                    scan_result.obfuscation = "encoding.base64"
                    scan_result = Node(
                        parent_node.type,
                        b64_string,
                        "",
                        0,
                        0,
                        parent_node.parent,
                        children=[scan_result],
                    )
                    yield scan_result.children[0]
                except binascii.Error:
                    pass


def manual_url_parsing(url):
    parsed_url = []
    for component, value in urlparse(url)._asdict().items():
        if component == "netloc":
            host = value
            username = password = None
            if "@" in host:
                password = None
                username, host = host.rsplit("@", 1)
                if ":" in username:
                    username, password = username.split(":", 1)
            parsed_url.append(
                Node("network.ip" if re.match(IP_ONLY_REGEX, host) else "network.domain", make_bytes(host))
            )
            if username:
                parsed_url.append(Node("network.url.username", make_bytes(username)))
            if password:
                parsed_url.append(Node("network.url.password", make_bytes(password)))
        else:
            parsed_url.append(Node(f"network.url.{component}", make_bytes(value)))
    return parsed_url


def url_analysis(
    url: str, lookup_safelist: Callable
) -> Tuple[ResultTableSection, Dict[str, List[str]], Dict[str, List[str]]]:
    # There is no point in searching for keywords in a URL
    md_registry = get_analyzers()
    md = Multidecoder(decoders=md_registry)

    analysis_table = ResultTableSection(url[:128] + "..." if len(url) > 128 else url)
    network_iocs = {ioc_type: [] for ioc_type in NETWORK_IOC_TYPES}
    flagged_behaviours = defaultdict(set)

    def add_MD_results_to_table(result: Node):
        if len(result.children) == 1 and result.value == result.children[0].value:
            # Two identical nodes in a row, merge the two nodes together
            if not result.obfuscation:
                result.obfuscation = result.children[0].obfuscation
            if not result.type:
                result.type = result.children[0].type
            result.children = result.children[0].children

        if result.type == URL_TYPE and not result.obfuscation:
            result.obfuscation = "encoding.url"
            result.start = 0
            result.end = len(result.parent.value)

        if isinstance(result.value, bytes):
            # Attempt to decode decoded string
            try:
                result.value.decode()
            except UnicodeDecodeError:
                # Garbage string decoded
                return

        value_str = make_str(result.value)
        analysis_table.add_row(
            TableRow(
                {
                    "COMPONENT": result.parent.type.split(".")[-1].upper(),
                    "ENCODED STRING": make_str(result.original if result.obfuscation else result.parent.value),
                    "OBFUSCATION": result.obfuscation,
                    "DECODED STRING": value_str,
                }
            )
        )

        if result.type == URL_TYPE:
            analysis_table.add_tag("network.static.uri", value_str)
            network_iocs["uri"].append(value_str)
            # Extract the host and append to tagging/set to be analyzed
            host_node = ([node for node in result.children if node.type in ["network.ip", "network.domain"]] + [None])[
                0
            ]
            if not host_node:
                pass
            elif host_node.type == DOMAIN_TYPE:
                analysis_table.add_tag("network.static.domain", host_node.value)
                network_iocs["domain"].append(host_node.value.decode())
            elif host_node.type == IP_TYPE:
                analysis_table.add_tag("network.static.ip", host_node.value)
                network_iocs["ip"].append(host_node.value.decode())
            inner_analysis_section, inner_network_iocs, inner_flagged_behaviours = url_analysis(
                value_str, lookup_safelist
            )
            if inner_analysis_section.body:
                # If we were able to analyze anything of interest recursively, append to result
                analysis_table.add_subsection(inner_analysis_section)
                # Merge found IOCs
                for ioc_type in NETWORK_IOC_TYPES:
                    network_iocs[ioc_type] = network_iocs[ioc_type] + inner_network_iocs[ioc_type]
                for k, v in inner_flagged_behaviours.items():
                    flagged_behaviours[k].update(v)
        elif result.type == EMAIL_TYPE:
            analysis_table.add_tag("network.email.address", value_str)
        elif result.type == DOMAIN_TYPE:
            analysis_table.add_tag("network.static.domain", value_str)
            network_iocs["domain"].append(value_str)
        elif result.type == IP_TYPE:
            analysis_table.add_tag("network.static.ip", value_str)
            network_iocs["ip"].append(value_str)

    # Process URL and see if there's any IOCs contained within
    try:
        parsed_url = parse_url(make_bytes(url))
    except UnicodeDecodeError:
        parsed_url = manual_url_parsing(url)

    scheme: Node = ([node for node in parsed_url if node.type == "network.url.scheme"] + [None])[0]
    scheme = "http" if not scheme else scheme.value.decode()
    host: Node = ([node for node in parsed_url if node.type in ["network.ip", "network.domain"]] + [None])[0]
    path: Node = ([node for node in parsed_url if node.type == "network.url.path"] + [None])[0]
    username: Node = ([node for node in parsed_url if node.type == "network.url.username"] + [None])[0]
    password: Node = ([node for node in parsed_url if node.type == "network.url.password"] + [None])[0]
    query: Node = ([node for node in parsed_url if node.type == "network.url.query"] + [None])[0]
    fragment: Node = ([node for node in parsed_url if node.type == "network.url.fragment"] + [None])[0]

    analysis_table.add_tag("network.static.uri", url)
    if host:
        if host.type == "network.domain":
            analysis_table.add_tag("network.static.domain", host.value)
        elif host.type == "network.ip":
            analysis_table.add_tag("network.static.ip", host.value)
            # Check for IP host obfuscation
            if host.obfuscation:
                # Add original URL as a parent node
                if not host.parent:
                    host.parent = Node("network.url", url)
                add_MD_results_to_table(host)

    # Check to see if there's anything "phishy" about the URL
    if username and host and host.type == "network.domain":
        domain = host.value.decode()
        target_url = f"{scheme}://{url[url.index(domain):]}"
        try:
            username_url = make_bytes(scheme) + b"://" + username.value
            username_as_url = parse_url(username_url.strip())
            # We usually look for 'network.ip' or 'network.domain' but we can assume that
            # any URL masquerading would be done using a domain only.
            # This also reduce false positives of having a number-only username being treated like an IP.
            username_host = ([node for node in username_as_url if node.type == "network.domain"] + [None])[0]
        except Exception:
            username_host = None

        if username_host:
            # Looks like URL might be masking the actual target
            analysis_table.add_row(
                TableRow(
                    {
                        "COMPONENT": "URL",
                        "ENCODED STRING": url,
                        "OBFUSCATION": "URL masquerade",
                        "DECODED STRING": target_url,
                    }
                )
            )
            domain_safelisted = False
            for analytic_type in ["static", "dynamic"]:
                qhash = hashlib.sha256(f"network.{analytic_type}.domain: {domain}".encode("utf8")).hexdigest()
                data = lookup_safelist(qhash)
                if data and data.get("enabled", False):
                    domain_safelisted = True

            if domain_safelisted:
                flagged_behaviours["safelisted_url_masquerade"].add(url)
            else:
                flagged_behaviours["url_masquerade"].add(url)
        elif password:
            # This URL has auth details embedded in the URL, weird
            analysis_table.add_row(
                TableRow(
                    {
                        "COMPONENT": "URL",
                        "ENCODED STRING": url,
                        "OBFUSCATION": "Embedded credentials",
                        "DECODED STRING": target_url,
                    }
                )
            )
            flagged_behaviours["embedded_credentials"].add(url)
        else:
            analysis_table.add_row(
                TableRow(
                    {
                        "COMPONENT": "URL",
                        "ENCODED STRING": url,
                        "OBFUSCATION": "Embedded username",
                        "DECODED STRING": target_url,
                    }
                )
            )
            flagged_behaviours["embedded_username"].add(url)

        analysis_table.add_tag("network.static.uri", url)
        analysis_table.add_tag("network.static.uri", target_url)
        network_iocs["uri"].append(target_url)
        network_iocs["domain"].append(domain)

    # Check for open redirects
    if host and path and host.type == "network.domain":
        # Google Travel
        if query and host.value.endswith(b"google.com") and path.value == b"/travel/clk":
            open_redirect = ResultSection("Open Redirect", parent=analysis_table)
            qs = parse_qs(query.value.decode())
            if "pcurl" in qs and isinstance(qs["pcurl"], list) and len(qs["pcurl"]) == 1:
                open_redirect.add_line(f"Possible abuse of Google travel/clk's open redirect to {qs['pcurl'][0]}")
                open_redirect.add_tag("network.static.uri", qs["pcurl"][0])
            # This shouldn't happen, but URI extraction is sometime flaky, so check for broken encoding in case
            elif "amp;pcurl" in qs and isinstance(qs["amp;pcurl"], list) and len(qs["amp;pcurl"]) == 1:
                open_redirect.add_line(f"Possible abuse of Google travel/clk's open redirect to {qs['amp;pcurl'][0]}")
                open_redirect.add_tag("network.static.uri", qs["amp;pcurl"][0])
            else:
                open_redirect.add_line(
                    "Possible abuse of Google travel/clk's open redirect but couldn't determine redirection target"
                )
        # Google AMP
        elif host.value.endswith(b"google.com") and path.value.startswith(b"/amp/"):
            open_redirect = ResultSection("Open Redirect", parent=analysis_table)
            redirect = path.value[5:]
            if redirect.startswith(b"s/"):
                redirect = redirect[2:]
            redirect = f"{scheme}://{unquote(redirect.decode())}"
            open_redirect.add_line(f"Possible abuse of Google AMP's open redirect to {redirect}")
            open_redirect.add_tag("network.static.uri", redirect)
        # Microsoft Login
        # https://medium.com/@coyemerald/f96a8fc807b6
        elif query and host.value == b"login.microsoftonline.com" and b"post_logout_redirect_uri" in query.value:
            open_redirect = ResultSection("Open Redirect", parent=analysis_table)
            qs = parse_qs(query.value.decode())
            if (
                "post_logout_redirect_uri" in qs
                and isinstance(qs["post_logout_redirect_uri"], list)
                and len(qs["post_logout_redirect_uri"]) == 1
            ):
                open_redirect.add_line(
                    f"Possible abuse of Microsoft Logout's open redirect to {qs['post_logout_redirect_uri'][0]}"
                )
                open_redirect.add_tag("network.static.uri", qs["post_logout_redirect_uri"][0])
        # Microsoft Medius
        # https://www.bleepingcomputer.com/news/security/threat-actors-abuse-google-amp-for-evasive-phishing-attacks/
        elif query and host.value == b"medius.microsoft.com" and path.value == b"/redirect":
            open_redirect = ResultSection("Open Redirect", parent=analysis_table)
            qs = parse_qs(query.value.decode())
            if "targeturl" in qs and isinstance(qs["targeturl"], list) and len(qs["targeturl"]) == 1:
                open_redirect.add_line(f"Possible abuse of Microsoft Medius' open redirect to {qs['targeturl'][0]}")
                open_redirect.add_tag("network.static.uri", qs["targeturl"][0])
        elif host.value in (
            b"urldefense.proofpoint.com",
            b"urldefense.com",
            b"urldefense.proofpoint.us",
            b"urldefense.us",
        ):
            try:
                decoded_url = URLDEFENSEDECODER.decode(url)
                result = Node(URL_TYPE, decoded_url.encode(), obfuscation="", end=len(url), parent=Node(URL_TYPE, url))
                add_MD_results_to_table(result)
            except ValueError:
                pass
        elif host.value == b"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo.ong" and path:
            # Assumes the query starts with '/l' and ends with 'ng'
            encoded = path.value.decode()[2:-2].replace("O", "1").replace("o", "0")
            decoded = "".join(chr(int(encoded[i : i + 8], 2)) for i in range(0, len(encoded), 8))
            if "\x00" in decoded:
                decoded = decoded.replace("\x00", "")
            result = Node(URL_TYPE, decoded, obfuscation="", end=len(url), parent=Node(URL_TYPE, url))
            add_MD_results_to_table(result)
        elif re.match(b"/...?/http", path.value):
            # Covers /L0/ or /CL0/ or other variations
            result = Node(
                URL_TYPE,
                unquote(path.value.split(b"/", 2)[-1]),
                obfuscation="",
                end=len(url),
                parent=Node(URL_TYPE, url),
            )
            add_MD_results_to_table(result)

    # Analyze query/fragment
    for segment in [query, fragment]:
        if segment:
            scan_result = md.scan_node(segment)
            if scan_result.children:
                # Something was found while analyzing
                for child in scan_result.children:
                    add_MD_results_to_table(child)
            #  Check for base64 encoded http | https URLs that MD didn't initially detect
            elif re.search(BASE64_RE, segment.value):
                # Nothing was found by MD so we'll have to perform some manual extraction
                for child_node in manual_base64_decode(segment, md):
                    add_MD_results_to_table(child_node)

    return analysis_table, {k: sorted(list(set(v))) for k, v in network_iocs.items()}, flagged_behaviours
