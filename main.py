from __future__ import annotations
import sys, os
from PySide6.QtWidgets import QApplication
from vault.ui import MainWindow, unlock_or_init

def main():
    app = QApplication(sys.argv)
    key = unlock_or_init()
    if not key:
        return 0
    w = MainWindow(key)
    w.resize(900, 520)
    w.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
