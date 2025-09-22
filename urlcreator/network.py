import binascii
import hashlib
import os
import pathlib
import re
from base64 import b64decode
from collections import defaultdict
from typing import Callable, Dict, List, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import requests
from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline_v4_service.common.result import (
    Heuristic,
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
from pymispwarninglists import WarningLists

import urlcreator.proofpoint

NETWORK_IOC_TYPES = ["domain", "ip", "uri"]

# Threshold to trigger heuristic regarding high port usage in URI
HIGH_PORT_MINIMUM = 1024

# Common tools native to the platform that can be used for recon
WINDOWS_TOOLS = ["dir", "hostname", "ipconfig", "netsh", "pwd", "route", "schtasks", "whoami"]
LINUX_TOOLS = ["crontab", "hostname", "iptables", "pwd", "route", "uname", "whoami"]

# Tools used for recon, sourced from https://github.com/ail-project/ail-framework/blob/master/bin/modules/Tools.py
# fmt: off
RECON_TOOLS = [
    "amap", "arachni", "armitage", "arpscan", "automater", "backdoorfactory", "beef", "braa", "cdpsnarf", "cge",
    "ciscotorch", "dig", "dirb", "dmytry", "dnmap", "dnscan", "dnsdict6", "dnsenum", "dnsmap", "dnsrecon", "dnstracer",
    "dotdotpwn", "dsfs", "dsjs", "dsss", "dsxs", "enum4linux", "fierce", "fimap", "firewalk", "fragroute",
    "fragrouter", "golismero", "goofile", "grabber", "hping3", "hydra", "identywaf", "intrace", "inurlbr",
    "ismtp", "jbossautopwn", "john", "joomscan", "keimpx", "knock", "lbd", "maskprocessor", "masscan", "miranda",
    "msfconsole", "ncat", "ncrack", "nessus", "netcat", "nikto", "nmap", "nslookup", "ohrwurm", "openvas", "oscanner",
    "p0f", "patator", "phrasendrescher", "polenum", "rainbowcrack", "rcracki_mt", "reconng", "rhawk", "searchsploit",
    "sfuzz", "sidguess", "skipfish", "smbmap", "sqlmap", "sqlninja", "sqlsus", "sslcaudit", "sslstrip", "sslyze",
    "striker", "tcpdump", "theharvester", "uniscan", "unixprivesccheck", "wafw00f", "whatwaf", "whois", "wig", "wpscan",
    "yersinia",
]

# Taken from https://github.com/obsidianforensics/unfurl/blob/v2025.08/unfurl/parsers/parse_shortlink.py#L118
EXTRA_SHORTENERS = [
    "bit.do", "buff.ly", "cutt.ly", "db.tt", "dlvr.it", "fb.me", "flip.it", "goo.gl", "ift.tt", "is.gd", "lc.chat",
    "nyti.ms", "ow.ly", "reut.rs", "sansurl.com", "snip.ly", "t.co", "t.ly", "tinyurl.com", "tr.im", "trib.al",
    "urlwee.com", "urlzs.com",
]
# fmt: on

ALL_TOOLS = set(
    [x.encode() for x in LINUX_TOOLS] + [x.encode() for x in WINDOWS_TOOLS] + [x.encode() for x in RECON_TOOLS]
)

MISP_SHORTENERS = WarningLists().warninglists["List of known URL Shorteners domains"].list

with open(os.path.join(pathlib.Path(__file__).parent.resolve(), "large_shorteners_list"), "r") as f:
    SHORTENERS = [x.strip() for x in f.readlines()]


def generic_behaviour(uris, behaviour_name, heuristic, score):
    behaviour_section = ResultSection(f"Behaviour {behaviour_name} found")
    heur = Heuristic(heuristic)
    heur.add_signature_id(behaviour_name, score)
    behaviour_section.set_heuristic(heur)
    for uri in sorted(uris):
        behaviour_section.add_line(uri)
        behaviour_section.add_tag("network.static.uri", uri)
    return behaviour_section


def high_port_behaviour(items):
    high_port_table = ResultTableSection("High Port Usage", heuristic=Heuristic(2))
    added_uri = set()
    for item in items:
        if item["URI"] in added_uri:
            continue
        added_uri.add(item["URI"])
        high_port_table.heuristic.add_signature_id("ip" if re.match(IP_ONLY_REGEX, item["HOST"]) else "domain")
        high_port_table.add_row(TableRow(item))
    return high_port_table


def tool_path_behaviour(items):
    tool_table = ResultTableSection("Discovery Tool Found in URI Path", heuristic=Heuristic(3))
    added_uri = set()
    for item in items:
        if item["URI"] in added_uri:
            continue
        added_uri.add(item["URI"])
        if item["TOOL"] in LINUX_TOOLS:
            tool_table.heuristic.add_signature_id("linux")
        if item["TOOL"] in WINDOWS_TOOLS:
            tool_table.heuristic.add_signature_id("windows")
        if item["TOOL"] in RECON_TOOLS:
            tool_table.heuristic.add_signature_id("recon")
        tool_table.add_row(TableRow(item))
    return tool_table


def potential_ip_download_behaviour(items):
    potential_ip_download = ResultTableSection(title_text="Potential IP-related File Downloads", heuristic=Heuristic(1))
    added_url = set()
    for item in items:
        if item["URL"] in added_url:
            continue
        added_url.add(item["URL"])
        potential_ip_download.add_row(TableRow(item))
        potential_ip_download.add_tag("network.static.uri", item["URL"])
        potential_ip_download.add_tag("network.static.ip", item["HOSTNAME"])
        potential_ip_download.heuristic.add_signature_id(f"ipv{item['IP_VERSION']}")
    return potential_ip_download


BEHAVIOURS = {
    "safelisted_url_masquerade": lambda uris: generic_behaviour(uris, "safelisted_url_masquerade", 4, 0),
    "url_masquerade": lambda uris: generic_behaviour(uris, "url_masquerade", 4, 500),
    "embedded_credentials": lambda uris: generic_behaviour(uris, "embedded_credentials", 4, 0),
    "embedded_username": lambda uris: generic_behaviour(uris, "embedded_username", 4, 0),
    "high_port": high_port_behaviour,
    "tool_path": tool_path_behaviour,
    "potential_ip_download": potential_ip_download_behaviour,
    "shorteners": lambda uris: generic_behaviour(uris, "shorteners", 4, 0),
}


class BehaviourDict(defaultdict):
    def __init__(self, *args, **kwargs):
        super().__init__(None, *args, **kwargs)
        self.struct_map = {
            "safelisted_url_masquerade": set,
            "url_masquerade": set,
            "embedded_credentials": set,
            "embedded_username": set,
            "high_port": list,
            "tool_path": list,
            "potential_ip_download": list,
            "shorteners": set,
        }

    def __missing__(self, key):
        struct_type = self.struct_map.get(key, set)
        self[key] = struct_type()
        return self[key]


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
                    scan_result = md.scan(b64decode(b64_string))
                    if not scan_result.children:
                        continue
                    scan_result = scan_result.children[0]
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


def expand_url_via_redirect_header(url):
    r = requests.get(url, allow_redirects=False)

    if r.status_code in [301, 302]:
        return r.headers["Location"]
    else:
        return {}


def url_analysis(
    url: str,
    lookup_safelist: Callable,
    remote_lookups: bool = False,
) -> Tuple[ResultTableSection, Dict[str, List[str]], Dict[str, List[str]]]:
    # There is no point in searching for keywords in a URL
    md_registry = get_analyzers()
    md = Multidecoder(decoders=md_registry)

    analysis_table = ResultTableSection(url[:128] + "..." if len(url) > 128 else url)
    network_iocs = {ioc_type: [] for ioc_type in NETWORK_IOC_TYPES}
    flagged_behaviours = BehaviourDict()

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
                value_str, lookup_safelist, remote_lookups
            )
            if inner_analysis_section.body:
                # If we were able to analyze anything of interest recursively, append to result
                analysis_table.add_subsection(inner_analysis_section)
            # Merge found IOCs
            for ioc_type in NETWORK_IOC_TYPES:
                network_iocs[ioc_type] = network_iocs[ioc_type] + inner_network_iocs[ioc_type]
            for k, v in inner_flagged_behaviours.items():
                flagged_behaviours[k].update(v) if isinstance(v, set) else flagged_behaviours[k].extend(v)
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
    except ValueError as e:
        if str(e) == "Invalid IPv6 URL":
            return analysis_table, network_iocs, flagged_behaviours
        raise

    scheme: Node = ([n for n in parsed_url if n.type == "network.url.scheme" and n.value != b""] + [None])[0]
    scheme = "http" if not scheme else scheme.value.decode()
    host: Node = ([n for n in parsed_url if n.type in ["network.ip", "network.domain"] and n.value != b""] + [None])[0]
    path: Node = ([node for node in parsed_url if node.type == "network.url.path" and node.value != b""] + [None])[0]
    username: Node = ([n for n in parsed_url if n.type == "network.url.username" and n.value != b""] + [None])[0]
    password: Node = ([n for n in parsed_url if n.type == "network.url.password" and n.value != b""] + [None])[0]
    query: Node = ([node for node in parsed_url if node.type == "network.url.query" and node.value != b""] + [None])[0]
    fragment: Node = ([n for n in parsed_url if n.type == "network.url.fragment" and n.value != b""] + [None])[0]

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

    urlparsed_url = urlparse(url)

    # Check for IP host with a path that looks like a file download
    if host and path and host.type == "network.ip" and b"." in os.path.basename(path.value):
        ip_version = "6" if host.value[0] == b"[" else "4"
        flagged_behaviours["potential_ip_download"].append(
            {"URL": url, "HOSTNAME": host.value.decode(), "IP_VERSION": ip_version, "PATH": path.value.decode()}
        )

    if host and host.type == "network.domain":
        host_value = host.value.decode()
        if host_value in SHORTENERS or host_value in MISP_SHORTENERS or host_value in EXTRA_SHORTENERS:
            flagged_behaviours["shorteners"].add(url)
            if remote_lookups and (redirection := expand_url_via_redirect_header(url)):
                result = Node(
                    URL_TYPE, redirection.encode(), obfuscation="shortener", end=len(url), parent=Node(URL_TYPE, url)
                )
                add_MD_results_to_table(result)

    # Check for high port usage
    try:
        if urlparsed_url.port and urlparsed_url.port > HIGH_PORT_MINIMUM:
            # High port usage associated to host
            flagged_behaviours["high_port"].append(
                {"URI": url, "HOST": urlparsed_url.hostname, "PORT": urlparsed_url.port}
            )
    except ValueError:
        # Invalid port during URI parsing, the URL is probably corrupted.
        return analysis_table, network_iocs, flagged_behaviours

    # Check if URI path is greater than the smallest tool we can look for (ie. '/ls')
    if path and len(path.value) > 2:
        path_split = path.value.lower().split(b"/")
        for tool in ALL_TOOLS:
            if tool in path_split:
                # Native OS tool found in URI path
                flagged_behaviours["tool_path"].append(
                    {"URI": url, "HOST": urlparsed_url.hostname, "TOOL": tool.decode()}
                )

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
            decoded_url = None
            try:
                decoded_url = urlcreator.proofpoint.decode(url)
            except (UnicodeDecodeError, ValueError, IndexError):
                pass
            if decoded_url and decoded_url != url:
                result = Node(
                    URL_TYPE,
                    decoded_url.encode(),
                    obfuscation="",
                    end=len(url),
                    parent=Node(URL_TYPE, url),
                )
                add_MD_results_to_table(result)
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
