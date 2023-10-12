from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTableSection, TableRow


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

        extracted_uri = ResultTableSection(title_text="Extracted URI")

        for tag_value, tag_score in urls:
            if tag_score >= minimum_maliciousness:
                request.add_extracted_uri(f"Score of {tag_score}", tag_value, request.get_uri_metadata(tag_value))
                extracted_uri.add_row(TableRow(dict(URL=tag_value, Score=tag_score)))
                extracted_uri.add_tag("network.static.uri", tag_value)

        if extracted_uri.body:
            request.result.add_section(extracted_uri)
