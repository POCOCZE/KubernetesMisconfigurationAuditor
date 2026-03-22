from dataclasses import dataclass, field
from unittest.mock import MagicMock
from main import KubernetesMisconfigurationAuditor
import pytest

@dataclass
class CpuMemory:
    cpu: str = field(default_factory=str)
    memory: str = field(default_factory=str)

@dataclass
class ContainerResource:
    requests: CpuMemory = field(default_factory=CpuMemory)
    limits: CpuMemory = field(default_factory=CpuMemory)

@dataclass
class SecurityContext:
    run_as_non_root: bool = field(default_factory=bool)

@dataclass
class LivenessProbe:
    initial_delay_seconds: int = field(default_factory=int)

@dataclass
class ReadinessProbe:
    initial_delay_seconds: int = field(default_factory=int)

@dataclass
class Container():
    resources: ContainerResource = field(default_factory=ContainerResource)
    security_context: SecurityContext | None = None
    # This line means that default type is None, but LivenessProbe can be also assigned. Great for imutable objects, for mutable ones the default_factory is best option.
    liveness_probe: LivenessProbe | None = None
    readiness_probe: ReadinessProbe | None = None

# This must be directly above the function that consumes it, otherwise error `fixture ABC not found`.
@pytest.mark.parametrize("image, expected", [
    ("nginx:latest", {"issue": "latest image tag", "severity": "high"}),
    ("nginx", {"issue": "no image tag (default: latest)", "severity": "high"}),
    ("nginx:1.26", None),
])

def test_image_tag(image, expected):
    auditor = KubernetesMisconfigurationAuditor()
    container = MagicMock()
    container.image = image

    result = auditor.check_image_tag(container)

    assert result == expected

def test_resources():
    auditor = KubernetesMisconfigurationAuditor()
    container = MagicMock()
    container.resources.requests = None
    container.resources.limits = None
    # This does not work: FAILED tests/test_auditor.py::test_resources - AttributeError: 'dict' object has no attribute 'requests'
    # container.resources = {}
    
    result = auditor.check_resources(container)

    assert result == {"issue": "no resources defined", "severity": "high"}

def test_resources_requests():
    auditor = KubernetesMisconfigurationAuditor()
    container = MagicMock()
    container.resources.requests = None
    
    result = auditor.check_resources(container)

    assert result == {"issue": "requests undefined", "severity": "medium"}

def test_resources_limits():
    auditor = KubernetesMisconfigurationAuditor()
    container = MagicMock()
    container.resources.limits = None
    
    result = auditor.check_resources(container)

    assert result == {"issue": "limits undefined", "severity": "low"}

def test_resources_defined():
    """
    Input have requests and limits defined.
    """
    auditor = KubernetesMisconfigurationAuditor()

    # This mock method works
    # container = MagicMock()
    # container.resources.requests.cpu = "4"
    # container.resources.requests.memory = "4Gi"
    # container.resources.limits.cpu = "8"
    # container.resources.limits.memory = "6Gi"

    # this works too
    # container = MagicMock()
    # container.resources.requests = {"cpu": "4", "memory": "4Gi"}
    # container.resources.limits = {"cpu": "8", "memory": "6Gi"}

    # This uses dataclass method
    requests = CpuMemory(cpu="4", memory="4Gi")
    limits = CpuMemory(cpu="8", memory="6Gi")
    resources = ContainerResource(requests, limits)
    container = Container(resources)

    # this method does not work
    # container.resources = {
    #     "limits": {
    #         "cpu": "4",
    #         "memory": "2Gi"
    #     },
    #     "requests": {
    #         "cpu": "2",
    #         "memory": "1Gi"
    #     }
    # }

    result = auditor.check_resources(container)

    assert result is None

def test_security_context_is_none():
    """
    Input security_context is None
    """
    auditor = KubernetesMisconfigurationAuditor()
    security_context = Container(security_context=None)

    result = auditor.check_security_context(security_context)

    assert result == {"issue": "container runs as root", "severity": "critical"}

def test_security_context_run_root():
    """
    Input security_context: run_as_non_root set to False
    """
    auditor = KubernetesMisconfigurationAuditor()
    run_as_non_root = SecurityContext(run_as_non_root=False)
    security_context = Container(security_context=run_as_non_root)

    result = auditor.check_security_context(security_context)

    assert result == {"issue": "container runs as root", "severity": "critical"}

def test_security_context_run_non_root():
    """
    Input security_context: run_as_non_root set to True
    """
    auditor = KubernetesMisconfigurationAuditor()
    run_as_non_root = SecurityContext(run_as_non_root=True)
    security_context = Container(security_context=run_as_non_root)

    result = auditor.check_security_context(security_context)

    assert result is None

def test_probes_nothing():
    """
    Input no probe
    """
    auditor = KubernetesMisconfigurationAuditor()
    liveness_probe = None
    readiness_probe = None
    probes = Container(liveness_probe=liveness_probe, readiness_probe=readiness_probe)

    result = auditor.check_probes(probes)

    assert result == {"issue": "probes undefined", "severity": "medium"}

def test_probes_liveness_only():
    """
    Input only liveness probe
    """
    auditor = KubernetesMisconfigurationAuditor()
    liveness_probe = LivenessProbe(initial_delay_seconds=1)
    readiness_probe = None
    probes = Container(liveness_probe=liveness_probe, readiness_probe=readiness_probe)

    result = auditor.check_probes(probes)

    assert result == {"issue": "readiness probe undefined", "severity": "medium"}

def test_probes_readiness_only():
    """
    Input only readiness probe
    """
    auditor = KubernetesMisconfigurationAuditor()
    liveness_probe = None
    readiness_probe = ReadinessProbe(initial_delay_seconds=1)
    probes = Container(liveness_probe=liveness_probe, readiness_probe=readiness_probe)

    result = auditor.check_probes(probes)

    assert result == {"issue": "liveness probe undefined", "severity": "medium"}

def test_probes_both():
    """
    Input both probes
    """
    auditor = KubernetesMisconfigurationAuditor()
    liveness_probe = LivenessProbe(initial_delay_seconds=1)
    readiness_probe = ReadinessProbe(initial_delay_seconds=1)
    probes = Container(liveness_probe=liveness_probe, readiness_probe=readiness_probe)

    result = auditor.check_probes(probes)

    assert result is None