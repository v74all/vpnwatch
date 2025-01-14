import sys
import asyncio
import signal
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
import functools

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QPushButton
from PyQt5.QtCore import QThreadPool
import uvloop
import aiodns
from prometheus_client import start_http_server, Counter, Gauge

from logger_singleton import LoggerSingleton
from constants import VERSION
from gui import VPNWatchApp, AnalysisWorker
from analyzer import perform_full_scan, get_system_ip

logger = LoggerSingleton.get_logger()

@dataclass
class AppMetrics:
    scan_count: Counter = Counter('vpn_scans_total', 'Total number of VPN scans')
    active_connections: Gauge = Counter('active_connections', 'Number of active connections')
    scan_duration: Gauge = Gauge('scan_duration_seconds', 'Scan duration in seconds')

class AsyncApp:
    def __init__(self):
        self.metrics = AppMetrics()
        self.dns_resolver = aiodns.DNSResolver()
        self.process_pool = ProcessPoolExecutor(max_workers=8)
        
    async def __aenter__(self) -> 'AsyncApp':
        start_http_server(9090)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.process_pool.shutdown()

def signal_handler(signum, frame):
    logger.info(f"Received signal {signum}")
    QtWidgets.QApplication.quit()

def setup_signal_handlers():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

@asynccontextmanager
async def application_context():
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    try:
        yield app
    finally:
        app.quit()
        await asyncio.sleep(0.1)

def _get_analysis_func(self, input_type: str):
    if input_type == "system_ip":
        return get_system_ip
    elif input_type == "direct_ip":
        return perform_full_scan
    elif input_type == "file":
        return lambda input_data: perform_full_scan(input_data, scan_type="file")
    elif input_type == "link":
        return lambda input_data: perform_full_scan(input_data, scan_type="link")
    elif input_type == "clipboard":
        return lambda input_data: perform_full_scan(input_data, scan_type="clipboard")
    else:
        return perform_full_scan

def _run_analysis_task(self, input_data: str, input_type: str, options: Optional[Dict[str, Any]] = None) -> None:
    self.progress.setValue(0)
    self.progress.show()
    
    try:
        timeout = options.get('timeout', 300) if options else 300
        analysis_func = self._get_analysis_func(input_type)
        
        if options is None:
            options = {}
        options['scan_type'] = input_type
        
        worker = AnalysisWorker(
            analysis_func,
            input_data,
            timeout=timeout,
            options=options,
            progress_callback=self._update_progress
        )
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(worker.signals.error.emit)
        self.statusBar().addWidget(self.cancel_btn)
        
        worker.signals.finished.connect(self._show_report)
        worker.signals.error.connect(self._on_error)
        worker.signals.progress.connect(self._update_progress)
        
        QThreadPool.globalInstance().start(worker)
        
    except Exception as e:
        self._on_error(str(e))
        self.progress.hide()
    finally:
        if hasattr(self, 'cancel_btn'):
            self.cancel_btn.setEnabled(False)

async def main():
    uvloop.install()
    
    try:
        logger.info(f"Starting V7lthronyx VPN Watch v{VERSION}")
        setup_signal_handlers()
        
        async with AsyncApp() as app:
            async with application_context() as qt_app:
                scan_results = await perform_full_scan("127.0.0.1")
                logger.info(f"Full scan results: {scan_results}")
                
                qt_app.setFont(QFont('Consolas', 10))
                window = VPNWatchApp()
                window.show()
                
                loop = asyncio.get_event_loop()
                future = loop.create_future()
                qt_app.aboutToQuit.connect(lambda: future.set_result(None) if not future.done() else None)
                
                while not future.done():
                    qt_app.processEvents()
                    await asyncio.sleep(0.01)
                await future
            
    except Exception as e:
        logger.critical(f"Failed to start GUI: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Application interrupted by user")
        sys.exit(0)
