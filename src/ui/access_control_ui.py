import sys
import json
import os
import socket
import threading
from datetime import datetime

from PyQt5.QtCore import Qt, QTimer, QDateTime, QSize
from PyQt5.QtGui import QIcon, QFont, QPixmap
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QStackedWidget, QPlainTextEdit, QSpacerItem,
    QSizePolicy, QDialog, QLineEdit, QToolButton, QFormLayout, QDialogButtonBox,
    QSpinBox, QMessageBox, QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QCheckBox
)

# ---------------- Global Variables ----------------
TCP_PORT = 5005
USER_FILE = "../data/users.json"  # Users stored as a dictionary (key = RFID)
monitor_events = []  # Global list of log events received via TCP


# ---------------- TCP Listener Implementation ----------------
def start_tcp_listener(update_monitor_callback):
    """
    Start a TCP listener on a background thread.
    For every received JSON event from the door unit, add a timestamp,
    append it to monitor_events, and schedule an update of the monitor display.
    """

    def listen():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", TCP_PORT))
        s.listen()
        print(f"[TCP] Listening on port {TCP_PORT}...")
        while True:
            conn, addr = s.accept()
            with conn:
                try:
                    data = conn.recv(1024).decode("utf-8")
                    if data:
                        print("[TCP] Received:", data)
                        event = json.loads(data)
                        event["timestamp"] = datetime.now().strftime("%H:%M:%S")
                        monitor_events.append(event)
                        # Use QTimer.singleShot to safely schedule an update on the main thread.
                        QTimer.singleShot(0, update_monitor_callback)
                except Exception as e:
                    print("[TCP] Error:", e)

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()


# ---------------- User Form Dialog ----------------
class UserFormDialog(QDialog):
    """
    Dialog to add or edit user information.
    If a user dictionary is provided, the dialog is in edit mode
    and prepopulates the fields.
    """

    def __init__(self, parent=None, user=None):
        super().__init__(parent)
        title = "Edit User" if user else "Add User"
        self.setWindowTitle(title)
        self.init_ui(user)

    def init_ui(self, user):
        layout = QFormLayout(self)

        self.rfid_edit = QLineEdit(self)
        self.name_edit = QLineEdit(self)
        self.admin_checkbox = QCheckBox(self)

        layout.addRow("RFID:", self.rfid_edit)
        layout.addRow("Name:", self.name_edit)
        layout.addRow("Admin?:", self.admin_checkbox)

        if user:
            self.rfid_edit.setText(user.get("rfid", ""))
            self.name_edit.setText(user.get("name", ""))
            self.admin_checkbox.setChecked(user.get("admin", False))

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def validate_and_accept(self):
        if not self.rfid_edit.text().strip() or not self.name_edit.text().strip():
            QMessageBox.warning(self, "Input Error", "Please fill in RFID and Name fields.")
            return
        self.accept()

    def get_data(self):
        return {
            "rfid": self.rfid_edit.text().strip(),
            "name": self.name_edit.text().strip(),
            "admin": self.admin_checkbox.isChecked()
        }


# ---------------- User Management Screen ----------------
class UserManagementScreen(QWidget):
    """
    Screen for managing users.
    Displays a table of current users with Edit and Delete buttons,
    plus an "Add User" button to open a form for adding new users.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.users = {}  # Stored as a dictionary keyed by RFID.
        self.init_ui()
        self.load_users()

    def init_ui(self):
        layout = QVBoxLayout(self)

        header_layout = QHBoxLayout()
        title_label = QLabel("User Management")
        title_label.setFont(QFont("Arial", 18))
        add_user_btn = QPushButton("Add User")
        add_user_btn.setMinimumHeight(40)
        add_user_btn.clicked.connect(self.open_add_user_dialog)
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(add_user_btn)
        layout.addLayout(header_layout)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["RFID", "Name", "Admin?", "Actions"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setDefaultSectionSize(60)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setStyleSheet("QHeaderView::section { background-color: #000000; color: #FFFFFF; padding: 4px; }")
        layout.addWidget(self.table)

    def load_users(self):
        if os.path.exists(USER_FILE):
            try:
                with open(USER_FILE) as infile:
                    self.users = json.load(infile)
            except Exception:
                self.users = {}
        else:
            self.users = {}
        self.populate_table()

    def populate_table(self):
        self.table.setRowCount(0)
        keys = list(self.users.keys())
        for row, key in enumerate(keys):
            user = self.users[key]
            # Ensure RFID is included in user data for editing.
            user["rfid"] = key

            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(key))
            self.table.setItem(row, 1, QTableWidgetItem(user.get("name", "")))
            admin_str = "Yes" if user.get("admin", False) else "No"
            self.table.setItem(row, 2, QTableWidgetItem(admin_str))

            btn_edit = QPushButton()
            btn_edit.setIcon(QIcon("../../resources/edit_white.png"))
            btn_edit.setIconSize(QSize(16, 16))
            btn_edit.clicked.connect(lambda ch, k=key: self.edit_user(k))

            btn_delete = QPushButton()
            btn_delete.setIcon(QIcon("../../resources/delete_white.png"))
            btn_delete.setIconSize(QSize(16, 16))
            btn_delete.clicked.connect(lambda ch, k=key: self.confirm_delete_user(k))

            actions_layout = QHBoxLayout()
            actions_layout.addWidget(btn_edit)
            actions_layout.addWidget(btn_delete)
            actions_layout.setContentsMargins(0, 0, 0, 0)
            actions_layout.setSpacing(5)
            actions_widget = QWidget()
            actions_widget.setLayout(actions_layout)
            self.table.setCellWidget(row, 3, actions_widget)

    def open_add_user_dialog(self):
        dlg = UserFormDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            new_user = dlg.get_data()
            rfid = new_user["rfid"]
            if rfid in self.users:
                QMessageBox.warning(self, "Duplicate RFID", f"A user with RFID {rfid} already exists.")
                return
            self.users[rfid] = new_user
            self.populate_table()
            self.save_users()

    def edit_user(self, key):
        user = self.users.get(key)
        if not user:
            QMessageBox.warning(self, "Edit Error", "User not found.")
            return
        dlg = UserFormDialog(self, user)
        if dlg.exec_() == QDialog.Accepted:
            updated_user = dlg.get_data()
            new_key = updated_user["rfid"]
            if new_key != key:
                if new_key in self.users:
                    QMessageBox.warning(self, "Duplicate RFID", f"A user with RFID {new_key} already exists.")
                    return
                del self.users[key]
                self.users[new_key] = updated_user
            else:
                self.users[key] = updated_user
            self.populate_table()
            self.save_users()

    def confirm_delete_user(self, key):
        user = self.users.get(key, {})
        reply = QMessageBox.question(
            self, "Delete User",
            f"Are you sure you want to delete '{user.get('name', '')}' (RFID: {key})?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            del self.users[key]
            self.populate_table()
            self.save_users()

    def save_users(self):
        try:
            with open(USER_FILE, "w") as outfile:
                json.dump(self.users, outfile, indent=4)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save users.json:\n{e}")


# ---------------- Admin Pin Dialog ----------------
class AdminPinDialog(QDialog):
    """
    Dialog to enter admin PIN for sensitive actions.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Admin PIN Required")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.pin_edit = QLineEdit()
        self.pin_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Enter Admin PIN:"))
        layout.addWidget(self.pin_edit)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_pin(self):
        return self.pin_edit.text().strip()


# ---------------- Main Access Control UI ----------------
class AccessControlUI(QWidget):
    def __init__(self):
        super().__init__()
        self.go_back_home = None
        self.init_ui()
        # Start the TCP listener to capture door scan events (log monitoring)
        start_tcp_listener(self.update_monitor_display)

    def init_ui(self):
        self.setWindowTitle("Door Access Control")
        self.setGeometry(100, 100, 800, 480)

        self.setStyleSheet("""
            QWidget {
                background-color: #294856;
                color: #FFFFFF;
            }
            QPushButton {
                background-color: #294856;
                color: #FFFFFF;
                border: none;
                border-radius: 10px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #4C6A72;
            }
            QLabel {
                font-size: 16px;
            }
            QPlainTextEdit {
                background-color: #FFFFFF;
                color: #000000;
            }
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(10)

        # ---------------- HEADER: Logo and Clock ----------------
        header_layout = QHBoxLayout()
        logo_label = QLabel()
        logo_pixmap = QPixmap("../../resources/Gatewise.PNG")
        logo_label.setPixmap(logo_pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_label.setFixedSize(70, 70)
        header_layout.addWidget(logo_label)
        header_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        self.clock_label = QLabel()
        self.clock_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        clock_font = QFont()
        clock_font.setPointSize(14)
        self.clock_label.setFont(clock_font)
        header_layout.addWidget(self.clock_label)
        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(self.update_clock)
        self.clock_timer.start(1000)
        self.update_clock()
        main_layout.addLayout(header_layout)

        # ---------------- CENTRAL AREA: QStackedWidget ----------------
        self.pages = QStackedWidget(self)
        self.main_page = QWidget()
        self.init_main_page()
        self.pages.addWidget(self.main_page)
        self.monitor_page = QWidget()
        self.init_monitor_page()
        self.pages.addWidget(self.monitor_page)
        self.admin_page = QWidget()
        self.init_admin_page()
        self.pages.addWidget(self.admin_page)
        self.user_mgmt_page = UserManagementScreen()
        self.pages.addWidget(self.user_mgmt_page)
        main_layout.addWidget(self.pages)

        # ---------------- BOTTOM CONTROLS ----------------
        bottom_layout = QHBoxLayout()
        self.go_back_home = QPushButton()
        self.go_back_home.setIcon(QIcon("../../resources/home_white.png"))
        self.go_back_home.setIconSize(QSize(48, 48))
        self.go_back_home.setMinimumSize(60, 60)
        self.go_back_home.clicked.connect(lambda: self.pages.setCurrentWidget(self.main_page))

        self.unlock_class_btn = QPushButton()
        self.unlock_class_btn.setIcon(QIcon("../../resources/unlock_for_class.png"))
        self.unlock_class_btn.setIconSize(QSize(48, 48))
        self.unlock_class_btn.setMinimumSize(60, 60)
        self.unlock_class_btn.setToolTip("Unlock for Class Duration")
        self.unlock_class_btn.clicked.connect(lambda: self.open_admin_pin("Class unlocked for 90 minutes"))
        bottom_layout.addWidget(self.go_back_home)
        bottom_layout.addWidget(self.unlock_class_btn)
        bottom_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        lock_btn = QPushButton()
        lock_btn.setIcon(QIcon("../../resources/lock_white.png"))
        lock_btn.setIconSize(QSize(48, 48))
        lock_btn.setToolTip("Lock Door")
        lock_btn.setMinimumSize(60, 60)
        lock_btn.clicked.connect(lambda: self.update_login_event("Door locked"))
        unlock_btn = QPushButton()
        unlock_btn.setIcon(QIcon("../../resources/unlock_white.png"))
        unlock_btn.setIconSize(QSize(48, 48))
        unlock_btn.setToolTip("Unlock Door")
        unlock_btn.setMinimumSize(60, 60)
        unlock_btn.clicked.connect(lambda: self.update_login_event("Door unlocked"))
        bottom_layout.addWidget(lock_btn)
        bottom_layout.addWidget(unlock_btn)
        main_layout.addLayout(bottom_layout)

        # ---------------- BOTTOM TEXT BOX for Last Login Event ----------------
        self.login_event_box = QLabel()
        self.login_event_box.setText("Last Login Event...")
        self.login_event_box.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.login_event_box)

    # ----- Page Initialization Methods -----
    def init_main_page(self):
        layout = QVBoxLayout(self.main_page)
        grid = QGridLayout()
        grid.setSpacing(40)
        icon_size = QSize(58, 58)
        btn_monitor = self.create_icon_button("Monitor Logs", "../../resources/logs-white.png", icon_size)
        btn_monitor.clicked.connect(lambda: self.pages.setCurrentWidget(self.monitor_page))
        grid.addWidget(btn_monitor, 0, 0, alignment=Qt.AlignCenter)
        btn_admin = self.create_icon_button("Admin", "../../resources/config_white.png", icon_size)
        btn_admin.clicked.connect(lambda: self.pages.setCurrentWidget(self.admin_page))
        grid.addWidget(btn_admin, 0, 1, alignment=Qt.AlignCenter)
        layout.addLayout(grid)

    def init_monitor_page(self):
        layout = QVBoxLayout(self.monitor_page)
        back_btn = QPushButton()
        back_btn.setIcon(QIcon("../../resources/back_white.png"))
        back_btn.setIconSize(QSize(32, 32))
        back_btn.clicked.connect(lambda: self.pages.setCurrentWidget(self.main_page))
        layout.addWidget(back_btn, alignment=Qt.AlignLeft)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlainText("Live log monitoring...\n")
        layout.addWidget(self.log_view)
        export_btn = QPushButton("Export to CSV")
        export_btn.clicked.connect(self.export_logs)
        layout.addWidget(export_btn, alignment=Qt.AlignRight)

    def init_admin_page(self):
        layout = QVBoxLayout(self.admin_page)
        back_btn = QPushButton()
        back_btn.setIcon(QIcon("../../resources/back_white.png"))
        back_btn.setIconSize(QSize(32, 32))
        back_btn.clicked.connect(lambda: self.pages.setCurrentWidget(self.main_page))
        layout.addWidget(back_btn, alignment=Qt.AlignLeft)
        blackout_label = QLabel("Blackout Schedule")
        layout.addWidget(blackout_label)
        unlock_length_layout = QHBoxLayout()
        length_label = QLabel("Unlock for Class Duration (minutes):")
        self.unlock_length_spin = QSpinBox()
        self.unlock_length_spin.setRange(10, 180)
        self.unlock_length_spin.setValue(90)
        unlock_length_layout.addWidget(length_label)
        unlock_length_layout.addWidget(self.unlock_length_spin)
        layout.addLayout(unlock_length_layout)
        user_config_btn = QPushButton("User Configuration")
        user_config_btn.clicked.connect(self.open_user_config)
        layout.addWidget(user_config_btn, alignment=Qt.AlignCenter)
        manage_users_btn = QPushButton("Manage Users")
        manage_users_btn.clicked.connect(lambda: self.pages.setCurrentWidget(self.user_mgmt_page))
        layout.addWidget(manage_users_btn, alignment=Qt.AlignCenter)

    # ----- Helper Methods -----
    def create_icon_button(self, text, icon_path, icon_size):
        button = QToolButton()
        button.setText(text)
        button.setIcon(QIcon(icon_path))
        button.setIconSize(icon_size)
        # If you want text under the icon, change ToolButtonStyle accordingly.
        button.setToolButtonStyle(Qt.ToolButtonIconOnly)
        button.setFont(QFont("Arial", 14))
        button.setMinimumSize(160, 160)
        button.setStyleSheet("""
            QToolButton { 
                text-align: center; 
                padding: 10px; 
                margin: 5px;
            }
        """)
        return button

    def update_clock(self):
        current_dt = QDateTime.currentDateTime()
        self.clock_label.setText(current_dt.toString("MM-dd-yyyy HH:mm:ss"))

    def export_logs(self):
        try:
            with open("exported_logs.csv", "w") as f:
                f.write("Log Message\n")
                for line in self.log_view.toPlainText().splitlines():
                    f.write(f"\"{line}\"\n")
            QMessageBox.information(self, "Export Successful", "Logs exported to exported_logs.csv")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def open_user_config(self):
        dlg = UserFormDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            self.user_mgmt_page.load_users()

    def update_login_event(self, message):
        self.login_event_box.setText(message)

    def open_admin_pin(self, event):
        dlg = AdminPinDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            pin = dlg.get_pin()
            test_pin = "1234"  # Ideally, load from config.json
            if pin != test_pin:
                QMessageBox.critical(self, "Invalid PIN", "Incorrect Admin PIN entered.")
                return
            else:
                self.update_login_event(event)

    def update_monitor_display(self):
        """
        Update the log view (self.log_view) with the latest monitor_events.
        Only the most recent 100 events are displayed.
        """
        if not hasattr(self, "log_view"):
            return
        self.log_view.clear()
        # Display events in reverse order (most recent first)
        for event in reversed(monitor_events[-100:]):
            line = f"{event.get('timestamp')} | Door: {event.get('door', 'Unknown')} | UID: {event.get('uid', '')} | Name: {event.get('name', '')} | Status: {event.get('status', '')}\n"
            self.log_view.appendPlainText(line)


# ---------------- Main Testing Block ----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AccessControlUI()
    window.show()
    sys.exit(app.exec_())
