import os
import re
from collections import Counter, defaultdict
from urllib.parse import urlparse

from assemblyline.odm.base import IP_ONLY_REGEX, IPV4_ONLY_REGEX
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)
from assemblyline_v4_service.common.task import MaxExtractedExceeded

import urlcreator.network

# Threshold to trigger heuristic regarding high port usage in URI
HIGH_PORT_MINIMUM = 1024

# Common tools native to the platform that can be used for recon
WINDOWS_TOOLS = ["dir", "hostname", "ipconfig", "netsh", "pwd", "route", "schtasks", "ver", "whoami"]
LINUX_TOOLS = ["cat", "crontab", "hostname", "iptables", "pwd", "route", "uname", "whoami"]

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
# fmt: on

ALL_TOOLS = set(LINUX_TOOLS + WINDOWS_TOOLS + RECON_TOOLS)


class URLCreator(ServiceBase):
    def __init__(self, config) -> None:
        super().__init__(config)
        self.minimum_maliciousness_limit = self.config.get("minimum_maliciousness_limit", 1)

    def execute(self, request: ServiceRequest) -> None:
        request.result = Result()

        minimum_maliciousness = max(int(request.get_param("minimum_maliciousness")), self.minimum_maliciousness_limit)
        tags = request.task.tags

        # Only concerned with static/dynamic URIs found by prior services
        urls = tags.get("network.static.uri", []) + tags.get("network.dynamic.uri", [])
        emails = [x[0].lower() for x in tags.get("network.email.address", [])]

        scoring_uri = ResultTableSection(title_text="High scoring URI")
        potential_ip_download = ResultTableSection(
            title_text="Potential IP-related File Downloads", heuristic=Heuristic(1)
        )
        high_port_table = ResultTableSection("High Port Usage", heuristic=Heuristic(2))
        tool_table = ResultTableSection("Discovery Tool Found in URI Path", heuristic=Heuristic(3))
        max_extracted_section = ResultTextSection("Too many URI files to be created")
        url_analysis_section = ResultSection("MultiDecoder Analysis")
        url_analysis_network_iocs = defaultdict(Counter)

        for tag_value, tag_score in urls:
            # Analyse the URL for the possibility of it being a something we should download
            parsed_url = urlparse(tag_value)
            if tag_value[len(parsed_url.scheme) + 3 :].rstrip("/").lower() in emails:
                continue
            interesting_features = []

            # Look for data that might be embedded in URLs
            analysis_table, network_iocs = urlcreator.network.url_analysis(tag_value)
            for k, v in network_iocs.items():
                url_analysis_network_iocs[k].update(v)
            if analysis_table.body:
                url_analysis_section.add_subsection(analysis_table)

            if tag_score >= minimum_maliciousness:
                scoring_uri.add_row(TableRow(dict(URL=tag_value, Score=tag_score)))
                scoring_uri.add_tag("network.static.uri", tag_value)
                interesting_features.append(f"Score of {tag_score}")

            if re.match(IP_ONLY_REGEX, parsed_url.hostname) and "." in os.path.basename(parsed_url.path):
                # If URL host is an IP and the path suggests it's downloading a file, it warrants attention
                ip_version = "4" if re.match(IPV4_ONLY_REGEX, parsed_url.hostname) else "6"
                potential_ip_download.add_row(
                    TableRow(
                        {
                            "URL": tag_value,
                            "HOSTNAME": parsed_url.hostname,
                            "IP_VERSION": ip_version,
                            "PATH": parsed_url.path,
                        }
                    )
                )
                potential_ip_download.add_tag("network.static.uri", tag_value)
                potential_ip_download.add_tag("network.static.ip", parsed_url.hostname)
                if not potential_ip_download.heuristic:
                    potential_ip_download.set_heuristic(3)
                potential_ip_download.heuristic.add_signature_id(f"ipv{ip_version}")
                interesting_features.append("IP as hostname")

            url_port = None
            try:
                url_port = parsed_url.port
            except ValueError as e:
                if str(e) == "Port out of range 0-65535":
                    # Port is out of range, probably an invalid URI
                    continue
                raise

            if url_port and url_port > HIGH_PORT_MINIMUM:
                # High port usage associated to host
                high_port_table.heuristic.add_signature_id(
                    "ip" if re.match(IP_ONLY_REGEX, parsed_url.hostname) else "domain"
                )
                high_port_table.add_row(TableRow({"URI": tag_value, "HOST": parsed_url.hostname, "PORT": url_port}))
                interesting_features.append("High port")

            # Check if URI path is greater than the smallest tool we can look for (ie. '/ls')
            if parsed_url.path and len(parsed_url.path) > 2:
                path_split = parsed_url.path.lower().split("/")
                for tool in ALL_TOOLS:
                    if tool in path_split:
                        # Native OS tool found in URI path
                        if tool in LINUX_TOOLS:
                            tool_table.heuristic.add_signature_id("linux")
                        if tool in WINDOWS_TOOLS:
                            tool_table.heuristic.add_signature_id("windows")
                        if tool in RECON_TOOLS:
                            tool_table.heuristic.add_signature_id("recon")

                        tool_table.add_row(TableRow({"URI": tag_value, "HOST": parsed_url.hostname, "TOOL": tool}))
                        interesting_features.append("Tool in path")

            if interesting_features:
                try:
                    request.add_extracted_uri(
                        f"Feature{'s' if len(interesting_features)>1 else ''}: {', '.join(interesting_features)}",
                        tag_value,
                        request.get_uri_metadata(tag_value),
                    )
                except MaxExtractedExceeded:
                    max_extracted_section.add_line(f"{tag_value}: {', '.join(interesting_features)}")

        if scoring_uri.body:
            request.result.add_section(scoring_uri)
        if potential_ip_download.body:
            request.result.add_section(potential_ip_download)
        if high_port_table.body:
            request.result.add_section(high_port_table)
        if tool_table.body:
            request.result.add_section(tool_table)
        if max_extracted_section.body:
            request.result.add_section(max_extracted_section)

        # Try to find redirector abuse. If there are multiple tags that are all
        # containing the same inner URL, that may be the final URI worth investigating
        if url_analysis_network_iocs:
            identical_sub_ioc = ResultSection("Identical sub IOC")
            for ioc, counter in url_analysis_network_iocs.items():
                sub_identical_sub_ioc = ResultTableSection(ioc)
                for elem, cnt in counter.items():
                    if cnt >= 5:
                        sub_identical_sub_ioc.add_row(TableRow({"IOC": elem, "Count": cnt}))
                        if ioc == "uri":
                            request.add_extracted_uri(
                                "Possible redirector abuse",
                                elem,
                                request.get_uri_metadata(elem),
                            )
                if sub_identical_sub_ioc.body:
                    identical_sub_ioc.add_subsection(sub_identical_sub_ioc)
            if identical_sub_ioc.subsections:
                url_analysis_section.add_subsection(identical_sub_ioc)

        if url_analysis_section.subsections:
            request.result.add_section(url_analysis_section)
