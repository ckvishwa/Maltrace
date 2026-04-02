import requests
import logging
import time
from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

BRIDGE = "http://192.168.75.1:9090"
VMX = "F:\\Vmware\\Windows_VM\\Windows10.vmx"
SNAPSHOT = "flare-clean"


class VMwareBridge(Machinery):
    module_name = "vmwarebridge"
    RUNNING = "running"
    POWEROFF = "poweroff"
    ABORTED = "abort"
    SAVED = "saved"

    def initialize(self):
        super().initialize()

    def start(self, label):
        log.info("VMwareBridge: reverting to snapshot %s", SNAPSHOT)
        try:
            requests.post(f"{BRIDGE}/snapshot/revert",
                json={"vmx": VMX, "snapshot": SNAPSHOT}, timeout=60)
            requests.post(f"{BRIDGE}/vm/start",
                json={"vmx": VMX}, timeout=60)
            log.info("VMwareBridge: VM started, waiting 30s for boot...")
            time.sleep(30)
            log.info("VMwareBridge: boot wait complete")
        except Exception as e:
            raise CuckooMachineError(f"Bridge error: {e}")

    def stop(self, label):
        log.info("VMwareBridge: stopping VM")
        try:
            requests.post(f"{BRIDGE}/vm/stop",
                json={"vmx": VMX}, timeout=30)
        except Exception as e:
            log.warning("Bridge stop error: %s", e)

    def _list(self):
        return ["flarevm"]

    def _status(self, label):
        return self.RUNNING

    def _wait_status(self, label, *states):
        return

    def shutdown_running_machines(self, configured_vms=None):
        log.info("VMwareBridge: skipping shutdown on startup")
        return