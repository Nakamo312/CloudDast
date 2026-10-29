"""Allowlisted external advisory pre-scan adapters."""

from cloud_dast.infrastructure.advisory.cache import (
    ADVISORY_CACHE_VERSION,
    FileAdvisoryCache,
    advisory_cache_key,
)
from cloud_dast.infrastructure.advisory.models import (
    AFFECTS,
    AdvisoryPackage,
    AdvisoryRecord,
    AdvisorySource,
    PackageVersion,
    VersionRange,
)
from cloud_dast.infrastructure.advisory.resolver import (
    ADVISORY_ADAPTER_VERSION,
    AdvisoryCorpus,
    AdvisoryFetcher,
    AdvisoryPreScanService,
    AdvisoryResolver,
    HttpsAdvisoryFetcher,
    project_affects,
)

__all__ = [
    "ADVISORY_ADAPTER_VERSION",
    "ADVISORY_CACHE_VERSION",
    "AFFECTS",
    "AdvisoryCorpus",
    "AdvisoryFetcher",
    "AdvisoryPackage",
    "AdvisoryPreScanService",
    "AdvisoryRecord",
    "AdvisoryResolver",
    "AdvisorySource",
    "FileAdvisoryCache",
    "HttpsAdvisoryFetcher",
    "PackageVersion",
    "VersionRange",
    "advisory_cache_key",
    "project_affects",
]
