from collections import Counter, defaultdict
from urllib.parse import urlparse

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)
from assemblyline_v4_service.common.task import MaxExtractedExceeded

import urlcreator.network


class URLCreator(ServiceBase):
    def __init__(self, config) -> None:
        super().__init__(config)
        self.minimum_maliciousness_limit = self.config.get("minimum_maliciousness_limit", 1)

    def execute(self, request: ServiceRequest) -> None:
        request.result = Result()
        tags = request.task.tags

        unc_http_paths = []
        for unc_path, _ in tags.get("network.static.unc_path", []):
            unc_path = "http:" + unc_path.replace("\\", "/")
            supposed_host = unc_path[5:].lstrip("/").split("/", 1)[0]
            if "@" in supposed_host:
                unc_path = unc_path.replace(supposed_host, supposed_host[::-1].replace("@", ":", 1)[::-1], 1)
            unc_http_paths.append(unc_path)
        if unc_http_paths:
            unc_to_http = ResultTextSection(
                title_text=f"UNC path{'s' if len(unc_http_paths) > 1 else ''} converted to HTTP", parent=request.result
            )
            for unc_http_path in unc_http_paths:
                unc_to_http.add_line(unc_http_path)
                unc_to_http.add_tag("network.static.uri", unc_http_path)

        # Only concerned with static/dynamic URIs found by prior services
        urls = tags.get("network.static.uri", []) + tags.get("network.dynamic.uri", [])

        # No tags of interest? Exit fast!
        if not urls:
            return

        minimum_maliciousness = max(int(request.get_param("minimum_maliciousness")), self.minimum_maliciousness_limit)
        emails = [x[0].lower() for x in tags.get("network.email.address", [])]

        scoring_uri = ResultTableSection(title_text="High scoring URI")
        max_extracted_section = ResultTextSection("Too many URI files to be created")
        url_analysis_section = ResultSection("MultiDecoder Analysis")
        url_analysis_network_iocs = defaultdict(Counter)
        flagged_behaviours = urlcreator.network.BehaviourDict()

        for tag_value, tag_score in urls:
            # Analyse the URL for the possibility of it being a something we should download
            parsed_url = urlparse(tag_value)
            if tag_value[len(parsed_url.scheme) + 3 :].rstrip("/").lower() in emails:
                continue
            if not parsed_url.hostname and not parsed_url.scheme:
                # Probably a corrupted tag
                continue

            interesting_features = []

            # Look for data that might be embedded in URLs
            remote_lookups = None
            if self.service_attributes.docker_config.allow_internet_access and request.get_param("use_internet"):
                remote_lookups = self.config["proxies"][request.get_param("proxy")] or ""
                remote_lookups = {"http": remote_lookups, "https": remote_lookups}
            analysis_table, network_iocs, tag_flagged_behaviours = urlcreator.network.url_analysis(
                tag_value, self.api_interface.lookup_safelist, remote_lookups
            )
            for k, v in network_iocs.items():
                url_analysis_network_iocs[k].update(v)
            for k, v in tag_flagged_behaviours.items():
                flagged_behaviours[k].update(v) if isinstance(v, set) else flagged_behaviours[k].extend(v)
            if analysis_table.body or analysis_table.subsections:
                url_analysis_section.add_subsection(analysis_table)

            if tag_score >= minimum_maliciousness:
                scoring_uri.add_row(TableRow(dict(URL=tag_value, Score=tag_score)))
                scoring_uri.add_tag("network.static.uri", tag_value)
                interesting_features.append(f"Score of {tag_score}")

            if "potential_ip_download" in tag_flagged_behaviours:
                # Make sure it's for the same uri
                for data in tag_flagged_behaviours["potential_ip_download"]:
                    if data["URL"] == tag_value:
                        interesting_features.append("IP as hostname")
                        break

            if "high_port" in tag_flagged_behaviours:
                # Make sure it's for the same uri
                for data in tag_flagged_behaviours["high_port"]:
                    if data["URI"] == tag_value:
                        interesting_features.append("High port")
                        break

            if "tool_path" in tag_flagged_behaviours:
                # Make sure it's for the same uri
                for data in tag_flagged_behaviours["tool_path"]:
                    if data["URI"] == tag_value:
                        interesting_features.append("Tool in path")
                        break

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
        if "potential_ip_download" in flagged_behaviours:
            potential_ip_download = urlcreator.network.BEHAVIOURS["potential_ip_download"](
                flagged_behaviours.pop("potential_ip_download")
            )
            request.result.add_section(potential_ip_download)
        if "high_port" in flagged_behaviours:
            high_port_table = urlcreator.network.BEHAVIOURS["high_port"](flagged_behaviours.pop("high_port"))
            request.result.add_section(high_port_table)
        if "tool_path" in flagged_behaviours:
            tool_table = urlcreator.network.BEHAVIOURS["tool_path"](flagged_behaviours.pop("tool_path"))
            request.result.add_section(tool_table)
        if max_extracted_section.body:
            request.result.add_section(max_extracted_section)

        if flagged_behaviours:
            for behaviour_name, uris in flagged_behaviours.items():
                behaviour_section = urlcreator.network.BEHAVIOURS[behaviour_name](uris)
                request.result.add_section(behaviour_section)

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

        if request.get_param("use_internet") and not self.service_attributes.docker_config.allow_internet_access:
            no_internet_section = ResultSection("No Internet", parent=request.result)
            no_internet_section.add_line(
                (
                    "Internet access was requested but is not allowed by the service configuration, "
                    "some results may be missing."
                )
            )
