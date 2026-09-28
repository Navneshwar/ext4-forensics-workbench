
from __future__ import annotations
import os
import psutil
from app.core.config import settings

def snapshot():
    cpu=psutil.cpu_percent(interval=0.1)
    vm=psutil.virtual_memory()
    rss=psutil.Process(os.getpid()).memory_info().rss
    if cpu>=90 or vm.percent>=88:
        rec_io,rec_hash=1,1
    elif cpu>=75 or vm.percent>=75:
        rec_io,rec_hash=min(2,settings.max_io_workers),1
    else:
        rec_io,rec_hash=settings.max_io_workers,settings.max_hash_workers
    return {
        "cpu_percent":cpu,"ram_percent":vm.percent,"ram_used_bytes":vm.used,
        "ram_total_bytes":vm.total,"ram_available_bytes":vm.available,
        "process_rss_bytes":rss,"cpu_count":os.cpu_count() or 1,
        "recommended_io_workers":rec_io,"recommended_hash_workers":rec_hash,
        "limits":{"max_io_workers":settings.max_io_workers,"max_hash_workers":settings.max_hash_workers}
    }
