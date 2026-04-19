"""IPv4 device discovery stages."""

from typing import List, Optional

from lanscape.core.scan_stage import ScanStageMixin
from lanscape.core.scan_context import ScanContext
from lanscape.core.models.enums import StageType
from lanscape.core.models.scan import ScanErrorInfo, StageEvalContext
from lanscape.core.scan_config import (
    ICMPDiscoveryStageConfig,
    ARPDiscoveryStageConfig,
    PokeARPDiscoveryStageConfig,
    ICMPARPDiscoveryStageConfig,
    ResilienceConfig,
)
from lanscape.core.models.scan import ScanWarningInfo
from lanscape.core.net_tools.device import Device
from lanscape.core.device_alive import IcmpLookup, ArpLookup, Poker
from lanscape.core.system_compat import query_single_arp_entry
from lanscape.core.ip_parser import IPAddress
from lanscape.core.decorators import job_tracker
from lanscape.core.threadpool_retry import (
    ThreadPoolRetryManager, RetryJob, RetryConfig, MultiplierController,
)


def _discover_device(
    ip: str,
    alive_fn,
    context: ScanContext,
    stage: ScanStageMixin,
    hostname_config,
) -> None:
    """Common pattern: check liveness, add device to context if alive."""
    device = Device(ip=ip)
    alive_fn(device)
    stage.increment()
    if device.alive:
        stage.log.debug("[%s] alive, resolving metadata", ip)
        device.stage = 'resolving'
        context.add_device(device)
        device.get_metadata(hostname_config=hostname_config)
        device.stage = 'found'


def _build_retry_infra(
    stage: ScanStageMixin,
    context: ScanContext,
    t_cnt: int,
    resilience: ResilienceConfig,
):
    """Build the retry manager + multiplier controller used by all discovery stages."""
    def on_warning(warning_type: str, warning_data: dict):
        context.warnings.append(ScanWarningInfo(
            type=warning_type,
            stage=stage.stage_name,
            **warning_data,
        ))
        stage.log.warning("Stage warning [%s]: %s", warning_type, warning_data.get("message", ""))

    mc = MultiplierController(
        initial_multiplier=resilience.t_multiplier,
        decrease_percent=resilience.failure_multiplier_decrease,
        debounce_sec=resilience.failure_debounce_sec,
        min_multiplier=0.1,
        on_warning=on_warning,
    )

    retry_config = RetryConfig(
        max_retries=resilience.failure_retry_cnt,
        multiplier_decrease=resilience.failure_multiplier_decrease,
        debounce_sec=resilience.failure_debounce_sec,
    )

    def on_error(job_id: str, error: Exception, tb_str: str):
        context.errors.append(ScanErrorInfo(
            basic=f"Error scanning IP {job_id}: {error}",
            traceback=tb_str,
        ))

    max_workers = max(1, int(t_cnt * resilience.t_multiplier))
    retry_manager = ThreadPoolRetryManager(
        max_workers=max_workers,
        retry_config=retry_config,
        multiplier_controller=mc,
        thread_name_prefix=stage.__class__.__name__,
        on_job_error=on_error,
    )
    return retry_manager, resilience.failure_retry_cnt


# ═══════════════════════════════════════════════════════════════════
#  ICMP Discovery
# ═══════════════════════════════════════════════════════════════════


class ICMPDiscoveryStage(ScanStageMixin):
    """Discover devices via ICMP echo requests (ping)."""

    stage_type = StageType.ICMP_DISCOVERY
    stage_name = "ICMP Discovery"
    counter_label = "IPs scanned"

    def __init__(
        self,
        cfg: ICMPDiscoveryStageConfig,
        subnet_ips: List[IPAddress],
        *,
        resilience: ResilienceConfig | None = None,
    ) -> None:
        super().__init__()
        self.cfg = cfg
        self.subnet_ips = subnet_ips
        self.resilience = resilience or ResilienceConfig()

    def can_execute(self, eval_ctx: StageEvalContext) -> Optional[str]:
        if eval_ctx.is_ipv6:
            return "ICMP discovery is IPv4-only"
        return None

    def execute(self, context: ScanContext) -> None:
        self.total = len(self.subnet_ips)
        retry_mgr, max_retries = _build_retry_infra(
            self, context, self.cfg.t_cnt, self.resilience,
        )

        @job_tracker
        def _check(ip_str: str):
            if not self.running:
                return
            device = Device(ip=ip_str)
            IcmpLookup.execute(device, self.cfg.ping_config)
            self.increment()
            if device.alive:
                self.log.debug("[%s] alive via ICMP", ip_str)
                device.stage = 'resolving'
                context.add_device(device)
                device.get_metadata(hostname_config=self.cfg.hostname_config)
                device.stage = 'found'

        jobs = [
            RetryJob(job_id=str(ip), func=_check, args=(str(ip),), max_retries=max_retries)
            for ip in self.subnet_ips
        ]
        retry_mgr.execute_all(jobs)


# ═══════════════════════════════════════════════════════════════════
#  ARP Broadcast Discovery  (IPv4 only)
# ═══════════════════════════════════════════════════════════════════


class ARPDiscoveryStage(ScanStageMixin):
    """Discover devices via Scapy ARP broadcast requests (IPv4 only)."""

    stage_type = StageType.ARP_DISCOVERY
    stage_name = "ARP Discovery"
    counter_label = "IPs scanned"

    def __init__(
        self,
        cfg: ARPDiscoveryStageConfig,
        subnet_ips: List[IPAddress],
        *,
        resilience: ResilienceConfig | None = None,
    ) -> None:
        super().__init__()
        self.cfg = cfg
        self.subnet_ips = subnet_ips
        self.resilience = resilience or ResilienceConfig()

    def can_execute(self, eval_ctx: StageEvalContext) -> Optional[str]:
        if eval_ctx.is_ipv6:
            return "ARP discovery is IPv4-only"
        if not eval_ctx.is_local:
            return "ARP requires a local IPv4 subnet"
        if not eval_ctx.arp_supported:
            return "ARP not supported on this system"
        return None

    def execute(self, context: ScanContext) -> None:
        self.total = len(self.subnet_ips)
        retry_mgr, max_retries = _build_retry_infra(
            self, context, self.cfg.t_cnt, self.resilience,
        )

        @job_tracker
        def _check(ip_str: str):
            if not self.running:
                return
            device = Device(ip=ip_str)
            ArpLookup.execute(device, self.cfg.arp_config)
            self.increment()
            if device.alive:
                self.log.debug("[%s] alive via ARP", ip_str)
                device.stage = 'resolving'
                context.add_device(device)
                device.get_metadata(hostname_config=self.cfg.hostname_config)
                device.stage = 'found'

        jobs = [
            RetryJob(job_id=str(ip), func=_check, args=(str(ip),), max_retries=max_retries)
            for ip in self.subnet_ips
        ]
        retry_mgr.execute_all(jobs)


# ═══════════════════════════════════════════════════════════════════
#  Poke → ARP Cache Discovery
# ═══════════════════════════════════════════════════════════════════


class PokeARPDiscoveryStage(ScanStageMixin):
    """Discover devices by TCP-poking then reading the OS ARP cache."""

    stage_type = StageType.POKE_ARP_DISCOVERY
    stage_name = "Poke → ARP Discovery"
    counter_label = "IPs scanned"

    def __init__(
        self,
        cfg: PokeARPDiscoveryStageConfig,
        subnet_ips: List[IPAddress],
        *,
        resilience: ResilienceConfig | None = None,
    ) -> None:
        super().__init__()
        self.cfg = cfg
        self.subnet_ips = subnet_ips
        self.resilience = resilience or ResilienceConfig()

    def can_execute(self, eval_ctx: StageEvalContext) -> Optional[str]:
        if eval_ctx.is_ipv6:
            return "Poke+ARP discovery is IPv4-only"
        if not eval_ctx.is_local:
            return "Poke+ARP requires a local IPv4 subnet"
        return None

    def execute(self, context: ScanContext) -> None:
        self.total = len(self.subnet_ips)
        retry_mgr, max_retries = _build_retry_infra(
            self, context, self.cfg.t_cnt, self.resilience,
        )

        @job_tracker
        def _check(ip_str: str):
            if not self.running:
                return
            device = Device(ip=ip_str)
            Poker.execute(device, self.cfg.poke_config)
            if not device.alive:
                mac = query_single_arp_entry(ip_str)
                if mac:
                    device.alive = True
                    device.macs = [mac]
            self.increment()
            if device.alive:
                self.log.debug("[%s] alive via Poke→ARP", ip_str)
                device.stage = 'resolving'
                context.add_device(device)
                device.get_metadata(hostname_config=self.cfg.hostname_config)
                device.stage = 'found'

        jobs = [
            RetryJob(job_id=str(ip), func=_check, args=(str(ip),), max_retries=max_retries)
            for ip in self.subnet_ips
        ]
        retry_mgr.execute_all(jobs)


# ═══════════════════════════════════════════════════════════════════
#  ICMP → ARP Cache Discovery
# ═══════════════════════════════════════════════════════════════════


class ICMPARPDiscoveryStage(ScanStageMixin):
    """Discover devices by ICMP ping then reading the OS ARP cache."""

    stage_type = StageType.ICMP_ARP_DISCOVERY
    stage_name = "ICMP → ARP Discovery"
    counter_label = "IPs scanned"

    def __init__(
        self,
        cfg: ICMPARPDiscoveryStageConfig,
        subnet_ips: List[IPAddress],
        *,
        resilience: ResilienceConfig | None = None,
    ) -> None:
        super().__init__()
        self.cfg = cfg
        self.subnet_ips = subnet_ips
        self.resilience = resilience or ResilienceConfig()

    def can_execute(self, eval_ctx: StageEvalContext) -> Optional[str]:
        if eval_ctx.is_ipv6:
            return "ICMP+ARP discovery is IPv4-only"
        if not eval_ctx.is_local:
            return "ICMP+ARP requires a local IPv4 subnet"
        return None

    def execute(self, context: ScanContext) -> None:
        self.total = len(self.subnet_ips)
        retry_mgr, max_retries = _build_retry_infra(
            self, context, self.cfg.t_cnt, self.resilience,
        )

        @job_tracker
        def _check(ip_str: str):
            if not self.running:
                return
            device = Device(ip=ip_str)
            IcmpLookup.execute(device, self.cfg.ping_config)
            if not device.alive:
                mac = query_single_arp_entry(ip_str)
                if mac:
                    device.alive = True
                    device.macs = [mac]
            self.increment()
            if device.alive:
                self.log.debug("[%s] alive via ICMP→ARP", ip_str)
                device.stage = 'resolving'
                context.add_device(device)
                device.get_metadata(hostname_config=self.cfg.hostname_config)
                device.stage = 'found'

        jobs = [
            RetryJob(job_id=str(ip), func=_check, args=(str(ip),), max_retries=max_retries)
            for ip in self.subnet_ips
        ]
        retry_mgr.execute_all(jobs)
