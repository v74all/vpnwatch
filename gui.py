
import asyncio
import json
import functools
from datetime import datetime
from typing import Optional, Dict, Any
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import QRunnable, QThreadPool, pyqtSignal, QObject, Qt
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QTabWidget, QStatusBar, QProgressBar, QDialog, QLineEdit, QGroupBox,
    QCheckBox, QSpinBox, QFileDialog, QMessageBox, QDialogButtonBox, QSizeGrip, QScrollArea,
    QInputDialog
)

from logger_singleton import LoggerSingleton
from constants import VERSION, AVAILABLE_APIS, DANGEROUS_PORTS, HIGH_RISK_PORTS
from analyzer import perform_full_scan, get_system_ip

logger = LoggerSingleton.get_logger()


def get_enhanced_style(base_size: int = 11) -> str:
    return f"""
    QMainWindow {{
        background-color: #0A0C1B;
        border: 1px solid #00FFA3;
        border-radius: 10px;
    }}
    
    QWidget {{
        color: #00FFA3;
        background-color: #0D1117;
        font-family: 'JetBrains Mono', 'Consolas', monospace;
        font-size: {base_size}pt;
        selection-background-color: #00CC88;
        selection-color: #000000;
        border-radius: 5px;
    }}
    
    QPushButton {{
        background-color: #162028;
        color: #00FFA3;
        border: 2px solid #00FFA3;
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: bold;
        min-width: 120px;
        margin: 2px;
        text-transform: uppercase;
    }}
    
    QPushButton:hover {{
        background-color: #00FFA3;
        color: #0A0C1B;
        border: 2px solid #00FFD1;
    }}
    
    QPushButton:pressed {{
        background-color: #008866;
        border: 2px solid #00CC88;
    }}
    
    QLabel#header {{
        color: #00FFD1;
        font-size: {base_size * 2.2}pt;
        font-weight: bold;
        padding: 20px;
        margin: 15px 0px;
        background-color: #101725;
        border: 2px solid #00FFA3;
        border-radius: 8px;
    }}
    
    QLineEdit {{
        background-color: #162028;
        color: #00FFA3;
        border: 2px solid #00FFA3;
        border-radius: 4px;
        padding: 5px;
        font-family: 'JetBrains Mono', 'Consolas', monospace;
    }}
    
    QLineEdit:focus {{
        border: 2px solid #00FFD1;
        background-color: #0D1117;
        border-width: 3px;
    }}
    
    QGroupBox {{
        border: 2px solid #00FFA3;
        border-radius: 6px;
        margin-top: 1em;
        padding-top: 1em;
        font-weight: bold;
    }}
    
    QGroupBox:hover {{
        border: 2px solid #00FFD1;
        border-width: 3px;
    }}
    
    # ...existing code...
    """


class AnalysisWorker(QRunnable):
    class Signals(QObject):
        finished = pyqtSignal(object)
        error = pyqtSignal(str)
        progress = pyqtSignal(dict)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.signals = self.Signals()
        self.progress_callback = self.kwargs.pop('progress_callback', None)

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            if self.progress_callback:
                self.kwargs['progress_callback'] = self.emit_progress

            try:
                if asyncio.iscoroutinefunction(self.func):
                    result = loop.run_until_complete(self.func(*self.args, **self.kwargs))
                else:
                    result = self.func(*self.args, **self.kwargs)
                self.signals.finished.emit(result)
            finally:
                loop.close()
        except Exception as e:
            logger.error(f"AnalysisWorker error: {e}")
            self.signals.error.emit(str(e))

    def emit_progress(self, progress: dict):
        self.signals.progress.emit(progress)


class ModernTab(QtWidgets.QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(5, 5, 5, 5)
        self.layout.setSpacing(5)

        header_layout = QHBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search in results...")
        self.search_box.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Fixed
        )
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setFixedWidth(100)
        self.copy_btn.clicked.connect(self.copy_content)
        header_layout.addWidget(self.search_box)
        header_layout.addWidget(self.copy_btn)
        self.layout.addLayout(header_layout)

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Expanding
        )
        self.layout.addWidget(self.text_area)

        self._original_content = ""
        self.search_box.textChanged.connect(self.filter_content)

    def on_resize(self, size: QtCore.QSize):
        font = self.text_area.font()
        font_size = int(min(size.width() / 100, size.height() / 50))
        font_size = max(8, min(font_size, 24))
        font.setPointSize(font_size)
        self.text_area.setFont(font)
        self.search_box.setFont(font)

    def set_content(self, text: str, is_html: bool = False):
        self._original_content = text
        if is_html:
            self.text_area.setHtml(text)
        else:
            self.text_area.setPlainText(text)

    def filter_content(self, text: str):
        if not text:
            self.text_area.setPlainText(self._original_content)
            return
        filtered = [line for line in self._original_content.split('\n') if text.lower() in line.lower()]
        self.text_area.setPlainText('\n'.join(filtered))

    def copy_content(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.text_area.toPlainText())


class ApiSettingsDialog(QDialog):
    def __init__(self, api_settings: Dict[str, str], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.api_settings = api_settings.copy()
        self.setWindowTitle("API Settings")
        self.setMinimumSize(400, 300)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

        title_label = QLabel("API Configuration")
        title_label.setObjectName("header")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(15)

        self.api_inputs = {}
        for api_name, api_info in AVAILABLE_APIS.items():
            group = QGroupBox(api_name)
            group_layout = QVBoxLayout()

            desc_label = QLabel(api_info.get("description", "No description provided."))
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("color: #00BB55; font-size: 10pt;")
            group_layout.addWidget(desc_label)

            key_layout = QHBoxLayout()
            key_label = QLabel("API Key:")
            key_label.setMinimumWidth(60)
            key_input = QLineEdit()
            key_input.setText(self.api_settings.get(api_name, ""))
            key_input.setEchoMode(QLineEdit.Password)
            key_input.setPlaceholderText("Enter API key here...")

            show_btn = QPushButton("👁")
            show_btn.setFixedWidth(30)
            show_btn.setToolTip("Show/Hide API Key")
     
            show_btn.clicked.connect(functools.partial(self.toggle_password_visibility, key_input))

            key_layout.addWidget(key_label)
            key_layout.addWidget(key_input, stretch=1)
            key_layout.addWidget(show_btn)
            group_layout.addLayout(key_layout)

            group.setLayout(group_layout)
            scroll_layout.addWidget(group)

            self.api_inputs[api_name] = key_input

        scroll_content.setLayout(scroll_layout)
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll, stretch=1)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        save_btn = QPushButton("Save")
        save_btn.setMinimumWidth(100)
        save_btn.clicked.connect(self.save_settings)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setMinimumWidth(100)
        cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

    def resizeEvent(self, event: QtGui.QResizeEvent):
        super().resizeEvent(event)
        base_size = min(self.width() / 80.0, self.height() / 40.0)
        font_size = max(8, min(int(base_size), 12))
        self.setStyleSheet(f"""
            QGroupBox {{
                font-size: {font_size + 1}pt;
                font-weight: bold;
                padding-top: 20px;
            }}
            QLabel {{
                font-size: {font_size}pt;
            }}
            QLineEdit {{
                font-size: {font_size}pt;
                padding: 5px;
            }}
            QPushButton {{
                font-size: {font_size}pt;
                padding: 5px 10px;
            }}
        """)

    def toggle_password_visibility(self, input_field: QLineEdit):
        if input_field.echoMode() == QLineEdit.Password:
            input_field.setEchoMode(QLineEdit.Normal)
        else:
            input_field.setEchoMode(QLineEdit.Password)

    def save_settings(self):
        for api_name, input_field in self.api_inputs.items():
            key = input_field.text().strip()
            if key:
                self.api_settings[api_name] = key
            else:
                self.api_settings.pop(api_name, None)
        self.accept()


class ScanOptionsDialog(QDialog):
    def __init__(self, scan_type: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.scan_type = scan_type
        self.setWindowTitle(f"{scan_type.title()} Scan Options")
        self.setMinimumWidth(400)
        self.setModal(True)

        layout = QVBoxLayout(self)


        ip_layout = QHBoxLayout()
        ip_label = QLabel("IP Address:")
        self.ip_input = QLineEdit()
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_input)
        layout.addLayout(ip_layout)


        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        self.checkboxes = {}


        scan_options = {
            "port": {
                "common_ports": "Scan Common Ports",
                "all_ports": "Scan All Ports (1-65535)",
                "custom_ports": "Custom Port Range",
            },
            "traceroute": {
                "max_30_hops": "Maximum 30 Hops",
                "resolve_hostnames": "Resolve Hostnames",
                "measure_latency": "Measure Latency",
            },
            "protocol": {
                "vpn_protocols": "VPN Protocols",
                "security_check": "Security Issues Check",
                "ssl_analysis": "SSL/TLS Analysis",
            },
            "full": {
                "port_scan": "Port Scanning",
                "traceroute": "Traceroute",
                "protocol_analysis": "Protocol Analysis",
                "dns_analysis": "DNS Analysis",
                "ssl_check": "SSL/TLS Check",
                "vuln_check": "Vulnerability Check",
            }
        }

        options = scan_options.get(scan_type, {})

        for key, text in options.items():
            cb = QCheckBox(text)
            cb.setChecked(True)  
            self.checkboxes[key] = cb
            options_layout.addWidget(cb)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)


        if scan_type == "port":
            self.port_range_group = QGroupBox("Custom Port Range")
            port_range_layout = QHBoxLayout()
            self.port_start = QSpinBox()
            self.port_start.setRange(1, 65535)
            self.port_start.setValue(1)
            self.port_end = QSpinBox()
            self.port_end.setRange(1, 65535)
            self.port_end.setValue(1024)
            port_range_layout.addWidget(QLabel("From:"))
            port_range_layout.addWidget(self.port_start)
            port_range_layout.addWidget(QLabel("To:"))
            port_range_layout.addWidget(self.port_end)
            self.port_range_group.setLayout(port_range_layout)
            self.port_range_group.setEnabled(False)
            layout.addWidget(self.port_range_group)

       
            self.checkboxes["custom_ports"].toggled.connect(self.port_range_group.setEnabled)

 
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setStyleSheet(get_enhanced_style())

    def get_selected_options(self) -> dict:
        options = {
            "scan_type": self.scan_type,
            "selected": {k: v.isChecked() for k, v in self.checkboxes.items()}
        }

   
        if self.scan_type == "port" and self.checkboxes.get("custom_ports", QCheckBox()).isChecked():
            options["port_range"] = {
                "start": self.port_start.value(),
                "end": self.port_end.value()
            }

        return options


class FlowLayout(QtWidgets.QLayout):
    def __init__(self, parent: Optional[QWidget] = None, margin: int = 0, spacing: int = -1):
        super().__init__(parent)
        self._items = []
        self.setContentsMargins(margin, margin, margin, margin)
        self.setSpacing(spacing)

    def addItem(self, item):
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> Optional[QtWidgets.QLayoutItem]:
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def takeAt(self, index: int) -> Optional[QtWidgets.QLayoutItem]:
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self) -> Qt.Orientations:
        return Qt.Orientations(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._do_layout(QtCore.QRect(0, 0, width, 0), True)

    def setGeometry(self, rect: QtCore.QRect):
        super().setGeometry(rect)
        self._do_layout(rect, False)

    def sizeHint(self) -> QtCore.QSize:
        return self.minimumSize()

    def minimumSize(self) -> QtCore.QSize:
        size = QtCore.QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margin = self.contentsMargins()
        size += QtCore.QSize(2 * margin.left(), 2 * margin.top())
        return size

    def _do_layout(self, rect: QtCore.QRect, test_only: bool) -> int:
        margin = self.contentsMargins()
        x = rect.x() + margin.left()
        y = rect.y() + margin.top()
        line_height = 0
        spacing = self.spacing()

        for item in self._items:
            widget = item.widget()
            if not widget:
                continue
            space_x = spacing
            space_y = spacing
            next_x = x + item.sizeHint().width() + space_x
            if next_x - space_x > rect.right() and line_height > 0:
                x = rect.x() + margin.left()
                y += line_height + space_y
                next_x = x + item.sizeHint().width() + space_x
                line_height = 0
            if not test_only:
                item.setGeometry(QtCore.QRect(QtCore.QPoint(x, y), item.sizeHint()))
            x = next_x
            line_height = max(line_height, item.sizeHint().height())

        return y + line_height - rect.y()


class ProgressArea(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.layout().setContentsMargins(10, 10, 10, 10)
        self.layout().setSpacing(10)

        self.step_counter = QLabel("준비 중...")
        self.step_counter.setAlignment(Qt.AlignCenter)
        self.step_counter.setStyleSheet("color: #00FFD1; font-weight: bold;")
        self.layout().addWidget(self.step_counter)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(25)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p% - %v/%m")
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #00FFA3;
                border-radius: 8px;
                background-color: #162028;
                text-align: center;
                color: #00FFA3;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00FFA3,
                    stop:0.5 #00FFD1,
                    stop:1 #00FFA3);
                border-radius: 6px;
            }
        """)
        self.layout().addWidget(self.progress_bar)

        self.current_op = QLabel()
        self.current_op.setAlignment(Qt.AlignCenter)
        self.current_op.setStyleSheet("color: #00FF66;")
        self.layout().addWidget(self.current_op)

        self.status_group = QGroupBox("스캔 상태")
        self.status_group.setStyleSheet("""
            QGroupBox {
                border: 2px solid #00FFA3;
                border-radius: 6px;
                margin-top: 1em;
                color: #00FFD1;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        status_layout = QVBoxLayout()
        self.status_list = QTextEdit()
        self.status_list.setReadOnly(True)
        self.status_list.setMaximumHeight(100)
        self.status_list.setStyleSheet("""
            QTextEdit {
                background-color: #162028;
                border: none;
                color: #00FF66;
            }
        """)
        status_layout.addWidget(self.status_list)
        self.status_group.setLayout(status_layout)
        self.layout().addWidget(self.status_group)

    def update_progress(self, info: dict):
        percentage = info.get('percentage', 0)
        current_step = info.get('current_step', 0)
        total_steps = info.get('total_steps', 0)
        message = info.get('message', '')
        scan_status = info.get('scan_status', {})

        self.progress_bar.setMaximum(total_steps)
        self.progress_bar.setValue(current_step)

        if current_step and total_steps:
            self.step_counter.setText(f"단계 {current_step} / {total_steps}")

        if message:
            self.current_op.setText(message)

        status_html = "<div style='color: #00FF66;'>"
        for op, status in scan_status.items():
            icon = "✓" if status else "✗"
            color = "#00FF66" if status else "#FF3333"
            status_html += f"<div style='color: {color};'>{icon} {op}</div>"
        status_html += "</div>"
        self.status_list.setHtml(status_html)

        if percentage == 100:
            self.current_op.setStyleSheet("color: #00FFD1; font-weight: bold;")
            self.current_op.setText("✨ 스캔 완료!")
        
        if info.get('error'):
            self.current_op.setStyleSheet("color: #FF3333; font-weight: bold;")
            self.current_op.setText(f"❌ {message}")

class VPNWatchApp(QMainWindow):
    def __init__(self):
        super().__init__()
        logger.info("Initializing VPNWatchApp GUI...")
        self.setWindowTitle("V7lthronyx - VPN Watch")
        self.setMinimumSize(800, 600)

        screen = QApplication.desktop().screenGeometry()
        width = min(int(screen.width() * 0.8), 1600)
        height = min(int(screen.height() * 0.8), 1000)
        self.setGeometry(
            (screen.width() - width) // 2,
            (screen.height() - height) // 2,
            width,
            height
        )

        self._scale_factor = 1.0
        self._base_font_size = 11
        self.api_settings = {api: "" for api in AVAILABLE_APIS.keys()}
        self.api_keys = {}
        self.thread_pool = QThreadPool()
        self.size_grip = QSizeGrip(self)
        self._window_state = Qt.WindowNoState
        self._current_data = None

        self._init_ui()
        self.update_styles()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        self._update_layout_margins(main_layout)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)

        header_label = QLabel("V7lthronyx VPN Watch")
        header_label.setObjectName("header")
        header_label.setAlignment(Qt.AlignCenter)
        content_layout.addWidget(header_label)

        version_label = QLabel(f"Version {VERSION} 🔥 BETA")
        version_label.setStyleSheet("""
            color: #00FFD1;
            font-weight: bold;
            padding: 5px 15px;
            border: 1px solid #00FFA3;
            border-radius: 10px;
            background: #162028;
        """)
        version_label.setAlignment(Qt.AlignCenter)
        content_layout.addWidget(version_label)

        toolbar = self._create_toolbar()
        content_layout.addWidget(toolbar)

        self.report_tabs = QTabWidget()
        self.summary_tab = ModernTab()
        self.security_tab = ModernTab()
        self.raw_data_tab = ModernTab()
        self.report_tabs.addTab(self.summary_tab, "Summary")
        self.report_tabs.addTab(self.security_tab, "Security")
        self.report_tabs.addTab(self.raw_data_tab, "Raw Data")
        content_layout.addWidget(self.report_tabs)

        scroll.setWidget(content_widget)
        main_layout.addWidget(scroll)

        status_widget = QWidget()
        status_layout = QHBoxLayout(status_widget)
        status_layout.setContentsMargins(5, 0, 5, 0)

        self.status_bar = QStatusBar()
        self.progress = QProgressBar()
        self.progress.setFixedHeight(15)
        self.progress.setMaximumWidth(200)
        self.progress.hide()

        status_layout.addWidget(self.status_bar, stretch=1)
        status_layout.addWidget(self.progress)
        main_layout.addWidget(status_widget)

        self.progress_area = ProgressArea()
        self.progress_area.hide()
        content_layout.addWidget(self.progress_area)

    def _create_toolbar(self) -> QWidget:
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setSpacing(10)

        flow_widget = QWidget()
        flow_layout = FlowLayout(flow_widget, margin=0, spacing=5)

        main_buttons = [
            ("Start New Scan", self.on_new_scan),
            ("Direct IP Analysis", self.on_direct_ip),
            ("My System IP", self.on_system_ip),
        ]

        scan_buttons = [
            ("Port Scan", lambda: self._run_specific_scan("port")),
            ("Traceroute", lambda: self._run_specific_scan("traceroute")),
            ("Protocol Analysis", lambda: self._run_specific_scan("protocol")),
        ]

        config_buttons = [
            ("Load Config File", self.on_load_file),
            ("Load Config URL", self.on_load_link),
            ("Load from Clipboard", self.on_load_clipboard),
            ("API Settings", self.on_api_settings)
        ]

        for text, handler in main_buttons + scan_buttons + config_buttons:
            btn = QPushButton(text)
            btn.clicked.connect(handler)
            btn.setSizePolicy(
                QtWidgets.QSizePolicy.Minimum,
                QtWidgets.QSizePolicy.Fixed
            )
            flow_layout.addWidget(btn)

        layout.addWidget(flow_widget)
        return toolbar

    def _run_specific_scan(self, scan_type: str):
        dialog = ScanOptionsDialog(scan_type, self)
        if dialog.exec_():
            ip = dialog.ip_input.text().strip()
            selected_options = dialog.get_selected_options()
            if not ip and scan_type != "system_ip":
                QMessageBox.warning(self, "Input Error", "IP address cannot be empty.")
                return
            self._run_analysis_task(ip, scan_type, selected_options)

    def _update_layout_margins(self, layout: QVBoxLayout):
        width = self.width()
        base_margin = 10
        if width < 800:
            margin = base_margin
        elif width < 1200:
            margin = base_margin * 1.5
        else:
            margin = base_margin * 2
        layout.setContentsMargins(
            int(margin), int(margin),
            int(margin), int(margin)
        )

    def update_styles(self):
        width = self.width()
        height = self.height()
        base_scale = min(width / 1000.0, height / 800.0)
        self._scale_factor = max(0.8, min(base_scale, 1.5))
        font_size = max(8, min(int(self._base_font_size * self._scale_factor), 14))
        self.setStyleSheet(get_enhanced_style(font_size))

    def resizeEvent(self, event: QtGui.QResizeEvent):
        super().resizeEvent(event)
        main_layout = self.centralWidget().layout()
        if (main_layout):
            self._update_layout_margins(main_layout)
        self.update_styles()
        self.size_grip.move(
            self.width() - self.size_grip.width(),
            self.height() - self.size_grip.height()
        )
        for i in range(self.report_tabs.count()):
            tab = self.report_tabs.widget(i)
            if hasattr(tab, 'on_resize'):
                tab.on_resize(event.size())

    def changeEvent(self, event: QtCore.QEvent):
        super().changeEvent(event)
        if event.type() == QtCore.QEvent.WindowStateChange:
            self._window_state = self.windowState()
            self._update_ui_for_state()

    def _update_ui_for_state(self):
        if self._window_state & Qt.WindowMaximized:
            self.size_grip.hide()
        else:
            self.size_grip.show()

    def _welcome_message(self):
        welcome_html = """
        <div style="text-align:center; margin-top:50px;">
            <h2 style="color:#00FFAA;">Welcome to V7lthronyx VPN Analyzer</h2>
            <p style="color:#00FF66;">Select a scan option above to begin...</p>
        </div>
        """
        self.summary_tab.set_content(welcome_html, is_html=True)

    def on_new_scan(self):
        self._current_data = None
        self.progress.hide()
        self.progress.setValue(0)
        self.status_bar.clearMessage()
        self._show_no_data_message()
        self._welcome_message()

    def on_direct_ip(self):
        ip, ok = QInputDialog.getText(self, "Direct IP Analysis", "Enter the IP address:")
        if ok:
            ip = ip.strip()
            if ip:
                self._run_analysis_task(ip, 'direct_ip')
            else:
                QMessageBox.warning(self, "Input Error", "IP address cannot be empty.")

    def on_system_ip(self):
        self._run_analysis_task("", 'system_ip')

    def on_load_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Configuration File", "", "All Files (*.*)")
        if file_path:
            self._run_analysis_task(file_path, 'file')

    def on_load_link(self):
        link, ok = QInputDialog.getText(self, "Load Configuration URL", "Enter the configuration URL:")
        if ok:
            link = link.strip()
            if link:
                self._run_analysis_task(link, 'link')
            else:
                QMessageBox.warning(self, "Input Error", "URL cannot be empty.")

    def on_load_clipboard(self):
        clipboard = QApplication.clipboard()
        text = clipboard.text().strip()
        if text:
            self._run_analysis_task(text, 'clipboard')
        else:
            QMessageBox.warning(self, "Warning", "Clipboard is empty.")

    def on_api_settings(self):
        dialog = ApiSettingsDialog(self.api_settings, self)
        if (dialog.exec_()):
            self.api_settings = dialog.api_settings
            self.api_keys.update(self.api_settings)
            logger.info("API keys updated")
            QMessageBox.information(self, "API Settings", "API keys have been updated successfully.")

    def _run_analysis_task(self, input_data: str, input_type: str, options: Optional[Dict[str, Any]] = None) -> None:
        self.progress.setValue(0)
        self.progress.show()
        
        try:
            timeout = options.get('timeout', 300) if options else 300
            
            if hasattr(self, 'cancel_btn'):
                self.statusBar().removeWidget(self.cancel_btn)
                self.cancel_btn.deleteLater()
            
            analysis_func = self._get_analysis_func(input_type)
            worker = AnalysisWorker(
                analysis_func,
                input_data,
                options=options or {},
                progress_callback=self._update_progress,
                timeout=timeout
            )
            
            self.cancel_btn = QPushButton("Cancel")
            self.cancel_btn.clicked.connect(lambda: self._handle_cancel(worker))
            self.statusBar().addWidget(self.cancel_btn)
            
            worker.signals.finished.connect(self._show_report)
            worker.signals.error.connect(self._on_error)
            worker.signals.progress.connect(self._update_progress)
            
            QThreadPool.globalInstance().start(worker)
            
        except Exception as e:
            self._on_error(str(e))
            self.progress.hide()

    def _handle_cancel(self, worker: AnalysisWorker):
        worker.signals.error.emit("Scan cancelled by user")
        if hasattr(self, 'cancel_btn'):
            self.statusBar().removeWidget(self.cancel_btn)
            self.cancel_btn.deleteLater()
            delattr(self, 'cancel_btn')

    def _get_analysis_func(self, input_type: str):
        if input_type == "system_ip":
            return get_system_ip
        elif input_type == "direct_ip":
            return perform_full_scan
        else:
            return functools.partial(perform_full_scan, input_type=input_type)

    def _calculate_risk_score(self, **analysis_results) -> int:
        score = 0
        weights = {
            'blacklist': 30,
            'ports': 25,
            'ssl': 20,
            'protocols': 15,
            'vulnerabilities': 10
        }

        blacklists = analysis_results.get('security', {}).get('blacklists', [])
        if blacklists:
            score += min(len(blacklists) * weights['blacklist'], weights['blacklist'])

        port_scan = analysis_results.get('port_scan', {})
        dangerous_ports = port_scan.get('dangerous_ports', [])
        high_risk_ports = port_scan.get('high_risk_ports', [])
        if dangerous_ports or high_risk_ports:
            score += (len(dangerous_ports) * 5 + len(high_risk_ports) * 3) * weights['ports'] // 20

        ssl_security = analysis_results.get('ssl_security', {})
        if ssl_security and not ssl_security.get('error'):
            for port_data in ssl_security.values():
                if isinstance(port_data, dict):
                    if port_data.get('vulnerabilities'):
                        score += weights['ssl']
                    if port_data.get('expired'):
                        score += weights['ssl'] // 2

        protocols = analysis_results.get('protocols', {})
        security_issues = protocols.get('security_issues', [])
        if security_issues:
            score += len(security_issues) * weights['protocols'] // 5

        vulnerabilities = analysis_results.get('vulnerabilities', {})
        if vulnerabilities:
            for vuln in vulnerabilities.values():
                if isinstance(vuln, dict):
                    severity = vuln.get('severity', 'Medium')
                    score += {
                        'Critical': 10,
                        'High': 7,
                        'Medium': 5,
                        'Low': 2
                    }.get(severity, 5)

        security_risk = analysis_results.get('security', {}).get('risk_level')
        if security_risk == 'High' and score < 60:
            score = max(score, 60)

        return min(100, int(score))

    def _get_risk_level(self, score: int) -> str:
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low'
        return 'Low'

    def _update_summary_tab(self, report: Dict[str, Any]):
        if report.get('security', {}).get('risk_level') == 'High' and report['risk_score'] == 0:
            report['risk_score'] = max(60, report['risk_score'])
            report['risk_level'] = self._get_risk_level(report['risk_score'])

        summary_html = self._generate_summary_html(report)
        self.summary_tab.set_content(summary_html, is_html=True)

    def _show_report(self, report: Any):
        self.progress.hide()
        self.status_bar.showMessage("Analysis Complete")
        self._current_data = report

        if isinstance(report, tuple):
            ip, hits = report
            report = {
                "ip": ip,
                "blacklists": hits,
                "timestamp": datetime.now().isoformat(),
                "valid": True,
                "type": "system_ip"
            }
            self._current_data = report

        if not report:
            self._show_no_data_message()
            return

        risk_score = self._calculate_risk_score(**report)
        risk_level = self._get_risk_level(risk_score)
        report["risk_score"] = risk_score
        report["risk_level"] = risk_level

        self._update_summary_tab(report)
        self._update_security_tab(report)
        self._update_raw_data_tab(report)

    def _show_no_data_message(self):
        no_data_html = """
        <div style='text-align:center; padding:20px;'>
            <h2 style='color:#FF3333;'>⚠️ No Data Available</h2>
            <p>The scan did not return any results. Please try again.</p>
        </div>
        """
        self.summary_tab.set_content(no_data_html, is_html=True)
        self.security_tab.set_content(no_data_html, is_html=True)
        self.raw_data_tab.set_content("{}")

    def _generate_summary_html(self, report: Dict[str, Any]) -> str:
        risk_score = report.get("risk_score", 0)
        risk_level = report.get("risk_level", "Unknown")
        
        summary_html = f"""
        <div style='padding:20px; font-family: "JetBrains Mono", monospace;'>
            <div style='background-color:#162028; padding:15px; border-radius:10px; border:2px solid #00FFA3;'>
                <h2 style='color:#00FFAA; text-align:center; margin-bottom:20px;'>
                    Scan Results: {report.get('ip', 'Unknown IP')}
                </h2>
                
                <!-- Status Overview -->
                <div style='display:grid; grid-template-columns:1fr 1fr; gap:15px; margin:20px 0;'>
                    {self._generate_status_overview_html(report)}
                    {self._generate_scan_details_html(report)}
                </div>

                <!-- Findings & Recommendations -->
                <div style='background-color:#1A1A1A; padding:15px; border-radius:8px; margin-top:15px;'>
                    <h3 style='color:#00FFD1;'>Key Findings & Recommendations</h3>
                    <div style='margin-top:10px;'>
                        {self._generate_findings_html(report)}
                        {self._generate_recommendations_html(report)}
                    </div>
                </div>
            </div>
        </div>
        """
        return summary_html

    def _generate_status_overview_html(self, report: Dict[str, Any]) -> str:
        risk_score = report.get("risk_score", 0)
        risk_level = report.get("risk_level", "Unknown")
        return f"""
        <div style='background-color:#1A1A1A; padding:15px; border-radius:8px;'>
            <h3 style='color:#00FFD1; margin-bottom:10px;'>Status Overview</h3>
            <p><b>Scan Status:</b> {'✅ Valid' if report.get('valid', False) else '❌ Invalid'}</p>
            <p><b>Risk Level:</b> <span style='color:{self._get_risk_color(risk_level)};'>
                {'🔴' if risk_level == 'Critical' else '🟡' if risk_level == 'Medium' else '🟢'} {risk_level}
            </span></p>
            <p><b>Risk Score:</b> 
                <div style='background:#0A0C1B; border-radius:10px; padding:5px; margin-top:5px;'>
                    <div style='background:{self._get_risk_color(risk_level)}; 
                              width:{risk_score}%; 
                              height:20px; 
                              border-radius:5px;
                              text-align:center;
                              color:#000;
                              font-weight:bold;'>
                        {risk_score}%
                    </div>
                </div>
            </p>
        </div>
        """

    def _generate_scan_details_html(self, report: Dict[str, Any]) -> str:
        return f"""
        <div style='background-color:#1A1A1A; padding:15px; border-radius:8px;'>
            <h3 style='color:#00FFD1; margin-bottom:10px;'>Scan Details</h3>
            <p><b>Scan Type:</b> {report.get('type', 'Full Scan').title()}</p>
            <p><b>Open Ports:</b> {len(report.get('port_scan', {}).get('open_ports', []))} found</p>
            <p><b>Completion:</b> {report.get('scan_completion', {}).get('percentage', 0):.1f}%</p>
        </div>
        """

    def _generate_findings_html(self, report: Dict[str, Any]) -> str:
        findings_html = ""
        if report.get('security', {}).get('blacklists'):
            findings_html += """
            <div style='background:#291111; padding:10px; border-radius:5px; margin:5px 0;'>
                <span style='color:#FF5555;'>⚠️ Blacklist Detection:</span>
                Found in blacklists - potential security risk
            </div>
            """

        dangerous_ports = report.get('port_scan', {}).get('dangerous_ports', [])
        if dangerous_ports:
            findings_html += f"""
            <div style='background:#291111; padding:10px; border-radius:5px; margin:5px 0;'>
                <span style='color:#FF5555;'>⚠️ Dangerous Ports:</span>
                {', '.join(map(str, dangerous_ports))} are open and potentially risky
            </div>
            """

        vulns = report.get('vulnerabilities', {})
        if vulns:
            findings_html += """
            <div style='background:#291111; padding:10px; border-radius:5px; margin:5px 0;'>
                <span style='color:#FF5555;'>⚠️ Vulnerabilities Detected</span>
                <ul style='margin:5px 0; padding-left:20px;'>
            """
            for vuln_type, details in vulns.items():
                findings_html += f"<li>{vuln_type}: {details.get('description', 'No details')}</li>"
            findings_html += "</ul></div>"

        return findings_html

    def _generate_recommendations_html(self, report: Dict[str, Any]) -> str:
        recommendations_html = ""
        if "analysis_summary" in report and report["analysis_summary"].get("recommendations"):
            recommendations_html += """
            <div style='background:#112911; padding:10px; border-radius:5px; margin:10px 0;'>
                <h4 style='color:#00FF66; margin:0 0 10px 0;'>🛡️ Recommended Actions:</h4>
                <ul style='margin:0; padding-left:20px;'>
            """
            for rec in report["analysis_summary"]["recommendations"]:
                recommendations_html += f"<li style='color:#00FF66;'>✓ {rec}</li>"
            recommendations_html += "</ul></div>"

        return recommendations_html

    def _format_detailed_security_info(self, results: Dict[str, Any]) -> str:
        return f"""
        <div style='padding:20px; font-family: "JetBrains Mono", monospace;'>
            <div style='background-color:#162028; padding:15px; border-radius:10px; border:2px solid #00FFA3;'>
                <h2 style='color:#00FFAA; text-align:center;'>Detailed Security Analysis</h2>
                
                <div style='margin:15px 0;'>
                    <h3 style='color:#00FFD1;'>🔍 Network Security</h3>
                    <div style='background:#1A1A1A; padding:15px; border-radius:8px;'>
                        {self._format_port_info(results.get('port_scan', {}))}
                    </div>
                </div>

                <div style='margin:15px 0;'>
                    <h3 style='color:#00FFD1;'>🛡️ SSL/TLS Security</h3>
                    <div style='background:#1A1A1A; padding:15px; border-radius:8px;'>
                        {self._format_ssl_info(results.get('ssl_security', {}))}
                    </div>
                </div>

                <div style='margin:15px 0;'>
                    <h3 style='color:#00FFD1;'>🌐 Network Path Analysis</h3>
                    <div style='background:#1A1A1A; padding:15px; border-radius:8px;'>
                        {self._format_traceroute_info(results.get('network_path', {}).get('traceroute', []))}
                    </div>
                </div>

                <div style='margin:15px 0;'>
                    <h3 style='color:#00FFD1;'>⚠️ Vulnerability Assessment</h3>
                    <div style='background:#1A1A1A; padding:15px; border-radius:8px;'>
                        {self._format_vulnerability_info(results.get('vulnerabilities', {}))}
                    </div>
                </div>
            </div>
        </div>
        """

    def _get_risk_color(self, risk_level: str) -> str:
        colors = {
            'Critical': '#FF0000',
            'High': '#FF6600',
            'Medium': '#FFCC00',
            'Low': '#00CC00',
            'Safe': '#00FF66',
            'Unknown': '#AAAAAA'
        }
        return colors.get(risk_level, '#AAAAAA')

    def _format_blacklist_info(self, blacklists: list) -> str:
        if not blacklists:
            return "<span style='color:#00FF66;'>No blacklist hits found</span>"
        return f"<span style='color:#FF5555;'>Found in {len(blacklists)} blacklists: {', '.join(blacklists)}</span>"

    def _format_port_info(self, ports: Dict[int, Dict[str, Any]]) -> str:
        if not ports:
            return "<span style='color:#00FF66;'>No open ports detected</span>"
        html = "<ul>"
        for port, info in ports.items():
            if port in DANGEROUS_PORTS:
                html += f"<li style='color:#FF5555;'>⚠️ Port {port} ({DANGEROUS_PORTS[port]}) - HIGH RISK</li>"
            elif port in HIGH_RISK_PORTS:
                html += f"<li style='color:#FFCC00;'>⚠️ Port {port} - MEDIUM RISK</li>"
            else:
                html += f"<li style='color:#00FF66;'>Port {port} - LOW RISK</li>"
        html += "</ul>"
        return html

    def _format_dns_info(self, dns_data: dict) -> str:
        if not dns_data:
            return "<p>No DNS information available</p>"
        html = "<ul>"
        for record_type, records in dns_data.items():
            if records and isinstance(records, list):
                html += f"<li><b>{record_type} Records:</b><ul>"
                for record in records:
                    html += f"<li>{record}</li>"
                html += "</ul></li>"
            elif records:
                html += f"<li><b>{record_type} Records:</b> {records}</li>"
        html += "</ul>"
        return html

    def _format_ssl_info(self, ssl_data: dict) -> str:
        if not ssl_data:
            return "<p>No SSL/TLS information available</p>"
        if ssl_data.get('error'):
            return f"<p style='color:#FF5555;'>SSL Error: {ssl_data['error']}</p>"
        html = "<ul>"
        if ssl_data.get('subject'):
            html += f"<li><b>Subject:</b> {ssl_data['subject'].get('CN', 'Unknown')}</li>"
        if ssl_data.get('issuer'):
            html += f"<li><b>Issuer:</b> {ssl_data['issuer'].get('CN', 'Unknown')}</li>"
        not_before = ssl_data.get('not_before', '')
        not_after = ssl_data.get('not_after', '')
        if not_before and not_after:
            html += f"<li><b>Valid Period:</b> {not_before} to {not_after}</li>"
        expired = ssl_data.get('expired', False)
        color = '#FF5555' if expired else '#00FF66'
        html += f"<li style='color:{color};'><b>Status:</b> {'Expired' if expired else 'Valid'}</li>"
        if ssl_data.get('cipher_suite'):
            cipher = ssl_data['cipher_suite']
            html += f"<li><b>Cipher Suite:</b> {cipher.get('name', 'Unknown')} ({cipher.get('bits', 'N/A')} bits)</li>"
        if ssl_data.get('vulnerabilities'):
            vuln = ssl_data['vulnerabilities']
            description = vuln.get('description', 'No description available.')
            html += f"""
            <li style='color:#FF5555;'><b>Vulnerabilities:</b>
                <ul><li>{description}</li></ul>
            </li>
            """
        html += "</ul>"
        return html

    def _format_traceroute_info(self, traceroute_data: list) -> str:
        if not traceroute_data:
            return "<p>No traceroute information available</p>"
        html = """
        <table style='width:100%; border-collapse:collapse;'>
            <tr style='background-color:#1A1A1A;'>
                <th>Hop</th><th>IP</th><th>Hostname</th><th>Latency</th>
            </tr>
        """
        for hop in traceroute_data:
            bg_color = '#1A1A1A' if hop.get('hop', 0) % 2 == 0 else '#222222'
            ip = hop.get('ip', 'N/A')
            hostname = hop.get('hostname', 'N/A')
            latency = f"{hop.get('latency', 'N/A')} ms" if hop.get('latency') else 'N/A'
            html += f"""
            <tr style='background-color:{bg_color};'>
                <td style='padding:5px;'>{hop.get('hop', 'N/A')}</td>
                <td style='padding:5px;'>{ip}</td>
                <td style='padding:5px;'>{hostname}</td>
                <td style='padding:5px;'>{latency}</td>
            </tr>
            """
        html += "</table>"
        return html

    def _format_vulnerability_info(self, vuln_data: dict) -> str:
        if not vuln_data:
            return "<p style='color:#00FF66;'>No vulnerabilities detected</p>"
        html = "<ul>"
        for vuln_type, details in vuln_data.items():
            severity = details.get('severity', 'Medium')
            severity_color = {
                'Critical': '#FF0000',
                'High': '#FF5555',
                'Medium': '#FFCC00',
                'Low': '#00FF66'
            }.get(severity, '#FFCC00')
            description = details.get('description', 'No description available.')
            html += f"""
            <li style='color:{severity_color};'>
                <b>{vuln_type.replace('_', ' ').title()}:</b><br>
                Severity: {severity}<br>
                {description}
            </li>
            """
        html += "</ul>"
        return html

    def _on_error(self, msg: str):
        logger.error(f"GUI Error: {msg}")
        self.progress.hide()
        self.status_bar.showMessage("Analysis Failed")
        error_html = f"""
        <div style='padding:10px;'>
            <h2 style='color:#FF3333;'>Error Occurred</h2>
            <p style='color:#FF5555;'>{msg}</p>
            <p style='color:#00FF66;'>Please try again or check the logs for more details.</p>
        </div>
        """
        self.summary_tab.set_content(error_html, is_html=True)
        QMessageBox.critical(
            self,
            "Error",
            f"An error occurred:\n{msg}\n\nPlease check the logs for more details."
        )

    def _show_detailed_report(self, results: Dict[str, Any]):
        completion_status = results.get("scan_completion", {})
        completion_html = f"""
        <div style='background-color:#1A1A1A; padding:10px; margin:5px; border-radius:5px;'>
            <h3>Scan Completion Status</h3>
            <p>Completed Steps: {completion_status.get('completed_steps', 0)} / {completion_status.get('total_steps', 0)}</p>
            <p>Completion: {completion_status.get('percentage', 0):.1f}%</p>
            
            <h4>Scan Status:</h4>
            <ul>
        """
        
        for scan_name, status in completion_status.get("scan_status", {}).items():
            color = '#00FF66' if status else '#FF3333'
            icon = '✓' if status else '✗'
            completion_html += f"<li style='color:{color};'>{icon} {scan_name}</li>"
        
        completion_html += "</ul></div>"
        
        security_html = "<div style='background-color:#1A1A1A; padding:10px; margin:5px; border-radius:5px;'>"
        security_html += "<h3>Security Findings</h3>"
        
        if results.get("security", {}).get("blacklists"):
            security_html += """
            <div style='color:#FF3333;'>
                <h4>⚠️ Blacklist Detections</h4>
                <ul>
            """
            for blacklist in results["security"]["blacklists"]:
                security_html += f"<li>{blacklist}</li>"
            security_html += "</ul></div>"
        
        if "analysis_summary" in results:
            summary = results["analysis_summary"]
            security_html += """
            <div style='margin-top:15px;'>
                <h4>Security Recommendations</h4>
                <ul>
            """
            for rec in summary.get("recommendations", []):
                security_html += f"<li style='color:#00FF66;'>✓ {rec}</li>"
            security_html += "</ul></div>"
        
        security_html += "</div>"
        
        self.summary_tab.set_content(completion_html + security_html, is_html=True)
        self.security_tab.set_content(self._format_detailed_security_info(results), is_html=True)
        self.raw_data_tab.set_content(json.dumps(results, indent=2))

    def _update_progress(self, info: dict):
        try:
            self.progress_area.show()
            
            percentage = info.get('percentage', 0)
            if percentage is not None:
                self.progress.setValue(percentage)
            
            message = info.get('message', '')
            if message:
                self.status_bar.showMessage(message)
            
            self.progress_area.update_progress(info)
            
            if percentage == 100:
                QtCore.QTimer.singleShot(3000, self.progress_area.hide)
                
            if info.get('error'):
                self.progress.hide()
                self.status_bar.showMessage("Error: " + str(info.get('message', 'Unknown error')))
                
        except Exception as e:
            logger.error(f"Error updating progress: {e}")
            self.status_bar.showMessage("Error updating progress")

    def _update_security_tab(self, report: Dict[str, Any]):
        security_html = self._format_detailed_security_info(report)
        self.security_tab.set_content(security_html, is_html=True)

    def _update_raw_data_tab(self, report: Dict[str, Any]):
        try:
            formatted_json = json.dumps(report, indent=2, sort_keys=True)
            self.raw_data_tab.set_content(formatted_json)
        except Exception as e:
            logger.error(f"Error formatting raw data: {e}")
            self.raw_data_tab.set_content("Error displaying raw data")


