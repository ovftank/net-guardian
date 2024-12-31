import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QLabel,
                             QMainWindow, QMessageBox, QProgressBar,
                             QPushButton, QTableWidget, QTableWidgetItem,
                             QVBoxLayout, QWidget)

from modules.netguardian import NetGuardian

STYLE_SHEET = """
QMainWindow {
    background-color: #1e1e1e;
}

QLabel {
    color: #ffffff;
    font-size: 13px;
}

QPushButton {
    background-color: #0d6efd;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 1px 10px;
    font-size: 13px;
    font-weight: 500;
    min-height: 25px;
}

QPushButton:hover {
    background-color: #0b5ed7;
}

QPushButton:pressed {
    background-color: #0a58ca;
}

QPushButton:disabled {
    background-color: #6c757d;
    opacity: 0.7;
}

QPushButton#controlBtn {
    background-color: #dc3545;
    border-radius: 6px;
    font-size: 13px;
    padding: 5px 15px;
}

QPushButton#controlBtn:hover {
    background-color: #c82333;
}

QTableWidget {
    background-color: #2d2d2d;
    color: #e0e0e0;
    gridline-color: #404040;
    border: 1px solid #404040;
    border-radius: 10px;
    font-size: 13px;
    selection-background-color: #264f78;
    padding: 5px;
}

QTableWidget::item {
    padding: 12px 8px;
    border: none;
}

QTableWidget::item:selected {
    background-color: #264f78;
    color: white;
}

QTableWidget::item:hover {
    background-color: #363636;
}

QHeaderView::section {
    background-color: #252525;
    color: #ffffff;
    padding: 12px 8px;
    border: none;
    font-size: 13px;
    font-weight: bold;
    border-bottom: 2px solid #404040;
}

QHeaderView::section:hover {
    background-color: #2a2a2a;
}

QPushButton#tableControlBtn {
    background-color: #dc3545;
    color: white;
    border: none;
    border-radius: 4px;
    min-width: 60px;
    font-size: 12px;
}

QPushButton#tableControlBtn:hover {
    background-color: #c82333;
}

QPushButton#tableControlBtn:pressed {
    background-color: #bd2130;
}

QFrame#statusFrame {
    background-color: #2d2d2d;
    border-radius: 10px;
    min-height: 60px;
    margin: 5px;
    padding: 0px 15px;
    border: 1px solid #404040;
}

QLabel#statusTitle {
    color: #8a8a8a;
    font-size: 13px;
    font-weight: 500;
}

QLabel#statusLabel {
    font-weight: bold;
    font-size: 14px;
}

QProgressBar {
    border: none;
    background-color: #2d2d2d;
    height: 4px;
    border-radius: 2px;
}

QProgressBar::chunk {
    background-color: #0d6efd;
    border-radius: 2px;
}

QLabel#loadingLabel {
    color: #ffc107;
    font-size: 13px;
    font-weight: 500;
}

QLabel#tableTitle {
    color: #ffffff;
    font-size: 15px;
    font-weight: bold;
    padding: 10px 0px;
}

QLabel#githubLink {
    color: #8a8a8a;
    font-size: 12px;
    padding: 10px;
}

QLabel#githubLink:hover {
    color: #0d6efd;
}

QTableWidget {
    padding: 10px;
    border: 1px solid #404040;
    border-radius: 10px;
}

QTableWidget::item {
    border-bottom: 1px solid #404040;
}
"""


class ScanThread(QThread):
    finished = pyqtSignal(list)

    def run(self):
        netcut = NetGuardian()
        devices = netcut.scan_network()
        self.finished.emit(devices)


class AttackThread(QThread):

    def __init__(self, netcut, target_ip):
        super().__init__()
        self.netcut = netcut
        self.target_ip = target_ip

    def run(self):
        if self.target_ip is None:
            self.netcut.start_control_all()
        else:
            self.netcut.start_control(self.target_ip)

    def stop(self):
        self.netcut.stop_control()


def get_icon_path(icon_name):
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return str(Path(sys._MEIPASS) / 'images' / icon_name)
    else:
        return str(Path(__file__).parent / 'images' / icon_name)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.netcut = NetGuardian()
        self.control_thread = None
        self.initUI()

    def initUI(self):
        self.setWindowIcon(QIcon(get_icon_path('icon.ico')))
        self.setWindowTitle('NetGuardian Pro - ovftank')
        self.setGeometry(100, 100, 1000, 600)
        self.setStyleSheet(STYLE_SHEET)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(20, 20, 20, 20)

        status_frame = QFrame()
        status_frame.setObjectName("statusFrame")
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(20, 10, 20, 10)
        status_layout.setSpacing(15)

        status_title = QLabel("Trạng thái:")
        status_title.setObjectName("statusTitle")
        self.status_label = QLabel('Sẵn sàng')
        self.status_label.setObjectName("statusLabel")

        status_layout.addWidget(status_title)
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()

        main_layout.addWidget(status_frame)

        table_label = QLabel("Danh sách thiết bị trong mạng:")
        table_label.setObjectName("tableTitle")
        main_layout.addWidget(table_label)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ['STT', 'IP', 'MAC', 'Hostname', 'Trạng thái', 'Chặn'])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setStyleSheet(self.table.styleSheet() + """
            QTableWidget::item:alternate {
                background-color: #333333;
            }
        """)
        self.table.horizontalHeader().setMinimumSectionSize(80)
        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(2, 180)
        self.table.setColumnWidth(3, 200)
        self.table.setColumnWidth(4, 120)
        self.table.setColumnWidth(5, 120)
        main_layout.addWidget(self.table)

        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)
        control_layout.setContentsMargins(0, 10, 0, 10)

        btn_scan = QPushButton('Quét thiết bị')
        btn_scan.setToolTip('Quét tất cả thiết bị trong mạng')
        btn_scan.clicked.connect(self.start_scan)

        self.btn_control_all = QPushButton('Chặn tất cả')
        self.btn_control_all.setToolTip('Chặn kết nối của tất cả thiết bị')
        self.btn_control_all.setObjectName("tableControlBtn")
        self.btn_control_all.clicked.connect(self.toggle_control_all)
        self.btn_control_all.setEnabled(False)

        control_layout.addWidget(btn_scan)
        control_layout.addWidget(self.btn_control_all)
        control_layout.addStretch()

        main_layout.addLayout(control_layout)

        self.loading_frame = QFrame()
        loading_layout = QVBoxLayout(self.loading_frame)
        loading_layout.setContentsMargins(20, 10, 20, 10)
        loading_layout.setSpacing(5)

        self.loading_label = QLabel("Đang quét thiết bị trong mạng...")
        self.loading_label.setObjectName("loadingLabel")
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setRange(0, 100)

        loading_layout.addWidget(self.loading_label)
        loading_layout.addWidget(self.progress_bar)

        self.loading_frame.hide()
        main_layout.addWidget(self.loading_frame)

        footer_layout = QHBoxLayout()

        github_link = QLabel(
            '<a href="https://github.com/ovftank/net-guardian">Built with ❤️ by @ovftank</a>')
        github_link.setObjectName("githubLink")
        github_link.setOpenExternalLinks(True)

        footer_layout.addStretch()
        footer_layout.addWidget(github_link)
        footer_layout.addStretch()

        main_layout.addLayout(footer_layout)

    def start_scan(self):
        self.table.setRowCount(0)
        self.status_label.setText('Đang quét mạng...')
        self.status_label.setStyleSheet("color: #ffc107;")

        self.loading_frame.show()
        self.progress_bar.setValue(0)

        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress)
        self.progress_timer.start(30)

        self.scan_thread = ScanThread()
        self.scan_thread.finished.connect(self.scan_completed)
        self.scan_thread.start()

    def update_progress(self):
        current = self.progress_bar.value()
        if current < 98:
            increment = max(1, (98 - current) // 10)
            self.progress_bar.setValue(current + increment)

        dots = "." * ((current // 10) % 4)
        self.loading_label.setText(f"Đang quét thiết bị trong mạng{dots}")

    def scan_completed(self, devices):
        try:
            self.progress_timer.stop()
            self.progress_bar.setValue(100)

            QTimer.singleShot(200, self.loading_frame.hide)

            if not devices:
                self.status_label.setText('Không tìm thấy thiết bị')
                self.status_label.setStyleSheet("color: #dc3545;")
                return

            self.devices = devices
            self.status_label.setText('Quét hoàn tất')
            self.status_label.setStyleSheet("color: #28a745;")
            self.update_table()
            self.btn_control_all.setEnabled(True)
        except Exception as e:
            self.status_label.setText('Lỗi khi quét mạng')
            self.status_label.setStyleSheet("color: #dc3545;")
            QMessageBox.critical(self, 'Lỗi', f'Đã xảy ra lỗi: {str(e)}')

    def update_table(self):
        self.table.setRowCount(len(self.devices))
        for idx, device in enumerate(self.devices):
            items = [
                str(idx + 1),
                device['ip'],
                device['mac'],
                device['hostname'],
                device['status']
            ]

            for col, value in enumerate(items):
                item = QTableWidgetItem(value)
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if col in [1, 2]:
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(idx, col, item)

            control_btn = QPushButton('Chặn')
            control_btn.setObjectName("tableControlBtn")
            control_btn.clicked.connect(
                lambda checked, ip=device['ip']: self.toggle_device_control(ip)
            )

            container = QWidget()
            layout = QHBoxLayout(container)
            layout.addWidget(control_btn)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            self.table.setCellWidget(idx, 5, container)
            self.table.setRowHeight(idx, 55)

        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 160)
        self.table.setColumnWidth(3, 180)
        self.table.setColumnWidth(4, 100)
        self.table.setColumnWidth(5, 120)

        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setHighlightSections(False)
        self.table.verticalHeader().setVisible(False)

    def toggle_control_all(self):
        if not self.control_thread or not self.control_thread.isRunning():
            if not self.devices:
                QMessageBox.warning(
                    self, 'Thông báo', 'Không có thiết bị nào để chặn')
                return

            self.control_thread = AttackThread(
                self.netcut, None)
            self.control_thread.start()

            self.btn_control_all.setText('Dừng chặn tất cả')
            self.status_label.setText('Đang chặn tất cả thiết bị')
            self.status_label.setStyleSheet("color: #dc3545;")

            self.btn_control_all.setEnabled(False)
        else:
            self.control_thread.stop()
            self.control_thread.quit()
            self.control_thread.wait()

            self.btn_control_all.setText('Chặn tất cả')
            self.status_label.setText('Đã dừng chặn')
            self.status_label.setStyleSheet("color: #28a745;")

            self.btn_control_all.setEnabled(True)

    def toggle_device_control(self, ip):
        btn = self.sender()
        if btn.text() == 'Chặn':
            self.netcut.start_control_device(ip)
            btn.setText('Dừng')
            btn.setStyleSheet("background-color: #dc3545;")
        else:
            self.netcut.stop_control_device(ip)
            btn.setText('Chặn')
            btn.setStyleSheet("")

        self.update_status()

    def update_status(self):
        controlled_count = len(self.netcut.target_ips)
        if controlled_count > 0:
            self.status_label.setText(
                f'Đang chặn {controlled_count} thiết bị')
            self.status_label.setStyleSheet("color: #dc3545;")
        else:
            self.status_label.setText('Sẵn sàng')
            self.status_label.setStyleSheet("color: #28a745;")

    def closeEvent(self, event):
        if self.control_thread and self.control_thread.isRunning():
            reply = QMessageBox.question(
                self, 'Xác nhận',
                'Đang trong quá trình chặn kết nối. Bạn có chắc muốn thoát?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.control_thread.stop()
                self.control_thread.quit()
                self.control_thread.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


if __name__ == '__main__':
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            QMessageBox.warning(
                None, 'Cảnh báo', 'Vui lòng chạy với quyền Administrator')
            sys.exit(1)
    except:
        pass

    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
