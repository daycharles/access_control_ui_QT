import sys
from PyQt5.QtWidgets import QApplication
from ui.access_control_ui import AccessControlUI

def main():
    app = QApplication(sys.argv)
    window = AccessControlUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
