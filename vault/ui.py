from __future__ import annotations
import sys, os, time, threading
from typing import Optional

from PySide6.QtWidgets import (
    QApplication, QWidget, QDialog, QMainWindow, QMessageBox,
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QHeaderView, QFormLayout, QTextEdit, QSpinBox, QCheckBox, QDialogButtonBox
)
from PySide6.QtGui import QIcon, QAction, QClipboard
from PySide6.QtCore import Qt, QTimer

from . import db, crypto, generator

APP_TITLE = "Password Vault — Ezhnya"

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Unlock Vault")
        layout = QVBoxLayout(self)

        self.info = QLabel("Enter master password")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.info)
        layout.addWidget(self.password)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def get_password(self) -> Optional[str]:
        if self.exec() == QDialog.Accepted:
            return self.password.text()
        return None

class EntryDialog(QDialog):
    def __init__(self, parent=None, title="Add Entry", data=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.ed_name = QLineEdit()
        self.ed_user = QLineEdit()
        self.ed_url = QLineEdit()
        self.ed_notes = QTextEdit()
        self.ed_pass = QLineEdit()
        self.ed_pass.setEchoMode(QLineEdit.Password)

        form.addRow("Name*", self.ed_name)
        form.addRow("Username", self.ed_user)
        form.addRow("URL", self.ed_url)
        form.addRow("Notes", self.ed_notes)
        form.addRow("Password*", self.ed_pass)
        layout.addLayout(form)

        # generator
        gen_box = QHBoxLayout()
        self.sp_len = QSpinBox()
        self.sp_len.setRange(8, 128)
        self.sp_len.setValue(16)
        self.cb_upper = QCheckBox("A‑Z")
        self.cb_upper.setChecked(True)
        self.cb_lower = QCheckBox("a‑z")
        self.cb_lower.setChecked(True)
        self.cb_digits = QCheckBox("0‑9")
        self.cb_digits.setChecked(True)
        self.cb_symbols = QCheckBox("!@#")
        self.cb_symbols.setChecked(True)
        self.cb_amb = QCheckBox("no similar")
        self.cb_amb.setChecked(True)
        btn_gen = QPushButton("Generate")
        btn_gen.clicked.connect(self._generate)

        for w in [QLabel("Length"), self.sp_len, self.cb_upper, self.cb_lower, self.cb_digits, self.cb_symbols, self.cb_amb, btn_gen]:
            gen_box.addWidget(w)
        layout.addLayout(gen_box)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

        if data:
            self.ed_name.setText(data.get("name",""))
            self.ed_user.setText(data.get("username",""))
            self.ed_url.setText(data.get("url",""))
            self.ed_notes.setPlainText(data.get("notes",""))
            self.ed_pass.setText(data.get("password",""))

    def _generate(self):
        pw = generator.generate_password(
            length=int(self.sp_len.value()),
            use_upper=self.cb_upper.isChecked(),
            use_lower=self.cb_lower.isChecked(),
            use_digits=self.cb_digits.isChecked(),
            use_symbols=self.cb_symbols.isChecked(),
            no_ambiguous=self.cb_amb.isChecked(),
        )
        self.ed_pass.setText(pw)

    def get_data(self):
        return {
            "name": self.ed_name.text().strip(),
            "username": self.ed_user.text().strip(),
            "url": self.ed_url.text().strip(),
            "notes": self.ed_notes.toPlainText().strip(),
            "password": self.ed_pass.text(),
        }

class MainWindow(QMainWindow):
    def __init__(self, key: bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle(APP_TITLE)
        self.key = key
        self.conn = db.connect()

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Username", "URL", "Created", "Updated"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.doubleClicked.connect(self.edit_selected)

        btn_add = QPushButton("Add")
        btn_edit = QPushButton("Edit")
        btn_del = QPushButton("Delete")
        btn_copy = QPushButton("Copy")
        btn_add.clicked.connect(self.add_entry)
        btn_edit.clicked.connect(self.edit_selected)
        btn_del.clicked.connect(self.delete_selected)
        btn_copy.clicked.connect(self.copy_password)

        top = QWidget()
        lay = QVBoxLayout(top)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        for b in (btn_add, btn_edit, btn_del, btn_copy):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        self.setCentralWidget(top)

        self.load_entries()

        # menu: Lock
        act_lock = QAction("Lock", self)
        act_lock.triggered.connect(self.lock_and_exit)
        self.menuBar().addAction(act_lock)

    def load_entries(self):
        self.table.setRowCount(0)
        for (id_, name, username, url, notes, created, updated) in db.list_entries(self.conn):
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(name))
            self.table.setItem(r, 1, QTableWidgetItem(username or ""))
            self.table.setItem(r, 2, QTableWidgetItem(url or ""))
            self.table.setItem(r, 3, QTableWidgetItem(time.strftime("%Y-%m-%d", time.localtime(created))))
            self.table.setItem(r, 4, QTableWidgetItem(time.strftime("%Y-%m-%d", time.localtime(updated))))
            # store id in first column
            self.table.item(r,0).setData(Qt.UserRole, id_)

    def _selected_id(self) -> Optional[int]:
        items = self.table.selectedItems()
        if not items:
            return None
        row = items[0].row()
        id_ = self.table.item(row,0).data(Qt.UserRole)
        return int(id_)

    def add_entry(self):
        dlg = EntryDialog(self, "Add Entry")
        if dlg.exec() == QDialog.Accepted:
            data = dlg.get_data()
            if not data["name"] or not data["password"]:
                QMessageBox.warning(self, "Error", "Name and Password are required.")
                return
            nonce, blob, _ = crypto.encrypt(self.key, data["password"].encode("utf-8"))
            db.add_entry(self.conn, data["name"], data["username"], data["url"], data["notes"], nonce, blob)
            self.load_entries()

    def edit_selected(self):
        id_ = self._selected_id()
        if not id_:
            return
        # fetch & decrypt password
        nonce, blob = db.get_entry_blob(self.conn, id_)
        try:
            password = crypto.decrypt(self.key, nonce, blob).decode("utf-8")
        except Exception:
            QMessageBox.critical(self, "Error", "Failed to decrypt entry.")
            return
        # read current visible row data
        row = self.table.currentRow()
        data = {
            "name": self.table.item(row,0).text(),
            "username": self.table.item(row,1).text(),
            "url": self.table.item(row,2).text(),
            "notes": "",  # notes aren't shown in table; keep empty
            "password": password,
        }
        dlg = EntryDialog(self, "Edit Entry", data=data)
        if dlg.exec() == QDialog.Accepted:
            new = dlg.get_data()
            if not new["name"] or not new["password"]:
                QMessageBox.warning(self, "Error", "Name and Password are required.")
                return
            nonce, blob, _ = crypto.encrypt(self.key, new["password"].encode("utf-8"))
            db.update_entry(self.conn, id_, new["name"], new["username"], new["url"], new["notes"], nonce, blob)
            self.load_entries()

    def delete_selected(self):
        id_ = self._selected_id()
        if not id_:
            return
        if QMessageBox.question(self, "Delete", "Delete selected entry?") == QMessageBox.Yes:
            db.delete_entry(self.conn, id_)
            self.load_entries()

    def copy_password(self):
        id_ = self._selected_id()
        if not id_:
            return
        nonce, blob = db.get_entry_blob(self.conn, id_)
        try:
            password = crypto.decrypt(self.key, nonce, blob).decode("utf-8")
        except Exception:
            QMessageBox.critical(self, "Error", "Failed to decrypt entry.")
            return
        QApplication.clipboard().setText(password, mode=QClipboard.Clipboard)
        QMessageBox.information(self, "Copied", "Password in clipboard. It will be cleared in 20 seconds.")
        # clear clipboard after 20 seconds in another thread
        def clear_clip():
            time.sleep(20)
            cb = QApplication.clipboard()
            if cb.text() == password:
                cb.clear()
        threading.Thread(target=clear_clip, daemon=True).start()

    def lock_and_exit(self):
        self.conn.close()
        self.close()

def unlock_or_init() -> Optional[bytes]:
    conn = db.connect()
    salt = db.get_meta(conn, "salt")
    check_nonce = db.get_meta(conn, "check_nonce")
    check_blob = db.get_meta(conn, "check_blob")

    dlg = LoginDialog()
    pwd = dlg.get_password()
    if pwd is None:
        return None

    if salt is None:
        # first time setup
        salt = crypto.new_salt()
        key = crypto.derive_key(pwd, salt)
        n, b = crypto.make_verifier(key)
        db.set_meta(conn, "salt", salt)
        db.set_meta(conn, "check_nonce", n)
        db.set_meta(conn, "check_blob", b)
        conn.close()
        return key
    else:
        key = crypto.derive_key(pwd, salt)
        if crypto.verify_verifier(key, check_nonce, check_blob):
            conn.close()
            return key
        else:
            QMessageBox.critical(None, "Error", "Invalid master password.")
            conn.close()
            return None
