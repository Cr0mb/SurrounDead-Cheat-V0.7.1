from __future__ import annotations

import sys
import time
import ctypes
import ctypes.wintypes
import struct
import threading
from typing import Iterable

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QCheckBox, QGroupBox
)
from PyQt5.QtCore import Qt, QPoint, QAbstractNativeEventFilter

# ============================================================
# CONFIG
# ============================================================

PROCESS_NAME = "SurrounDead-Win64-Shipping.exe"

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

WRITE_INTERVAL_SEC = 0.25

GOD_VALUES = {
    "Health": 9999.0,
    "Stamina": 9999.0,
    "Hunger": 9999.0,
    "Water": 9999.0,
}


CHEAT_STYLE = """
* {
    font-family: Segoe UI;
    font-size: 11px;
    color: #E6E6E6;
}

QWidget {
    background-color: #121417;
}

#TitleBar {
    background-color: #0C0E11;
    border-bottom: 1px solid #1E2228;
}

#TitleLabel {
    font-weight: bold;
    font-size: 12px;
}

QPushButton {
    background-color: #1E2228;
    border: 1px solid #2A2F36;
    padding: 6px;
    border-radius: 4px;
}

QPushButton:hover {
    background-color: #2A2F36;
}

QCheckBox {
    spacing: 10px;
}

QCheckBox::indicator {
    width: 36px;
    height: 18px;
    border-radius: 9px;
    background: #2A2F36;
}

QCheckBox::indicator:checked {
    background: #4CAF50;
}

QGroupBox {
    border: 1px solid #1E2228;
    border-radius: 6px;
    margin-top: 10px;
}

QGroupBox:title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 4px 8px;
    background-color: #121417;
}
"""


user32 = ctypes.WinDLL("user32", use_last_error=True)

WM_HOTKEY = 0x0312
VK_INSERT = 0x2D
HOTKEY_ID = 1


class HotkeyFilter(QAbstractNativeEventFilter):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def nativeEventFilter(self, eventType, message):
        if eventType != "windows_generic_MSG":
            return False, 0

        msg = ctypes.wintypes.MSG.from_address(int(message))
        if msg.message == WM_HOTKEY and msg.wParam == HOTKEY_ID:
            try:
                self.callback()
            except Exception:
                pass
            return True, 0

        return False, 0



kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_uint32),
        ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase", ctypes.c_int32),
        ("dwFlags", ctypes.c_uint32),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("th32ModuleID", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("GlblcntUsage", ctypes.c_uint32),
        ("ProccntUsage", ctypes.c_uint32),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", ctypes.c_uint32),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


# ============================================================
# MEMORY HELPERS
# ============================================================

def _check(h, msg):
    if not h or h == INVALID_HANDLE_VALUE:
        raise OSError(msg)
    return h


def get_pid(name: str) -> int:
    snap = _check(kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), "proc snap")
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)
        kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while True:
            if pe.szExeFile.lower() == name.lower():
                return pe.th32ProcessID
            if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                break
    finally:
        kernel32.CloseHandle(snap)
    raise ProcessLookupError(name)


def get_module_base(pid: int, module: str) -> int:
    snap = _check(
        kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
        ),
        "module snap",
    )
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(me)
        kernel32.Module32FirstW(snap, ctypes.byref(me))
        while True:
            if me.szModule.lower() == module.lower():
                return ctypes.addressof(me.modBaseAddr.contents)
            if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                break
    finally:
        kernel32.CloseHandle(snap)
    raise LookupError(module)


def open_process(pid: int):
    return _check(
        kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            False,
            pid,
        ),
        "OpenProcess",
    )


def read_u64(hproc, addr: int) -> int:
    buf = ctypes.c_ulonglong()
    kernel32.ReadProcessMemory(
        hproc, ctypes.c_void_p(addr),
        ctypes.byref(buf), 8, None
    )
    return buf.value


def write_double(hproc, addr: int, value: float):
    data = struct.pack("<d", float(value))
    kernel32.WriteProcessMemory(
        hproc,
        ctypes.c_void_p(addr),
        data,
        len(data),
        None,
    )


def read_ptr_chain(hproc, base: int, offsets: Iterable[int]) -> int:
    addr = base
    for off in offsets:
        addr = read_u64(hproc, addr) + off
    return addr


# ============================================================
# OFFSETS
# ============================================================

STATS = {
    "Health":  {"base": 0x06C61650, "offsets": [0xC0, 0x2E8, 0x7D0, 0xD0]},
    "Stamina": {"base": 0x06C61650, "offsets": [0x0, 0x330, 0x278, 0x28, 0xC8]},
    "Hunger":  {"base": 0x06CEBC60, "offsets": [0x4B0, 0x218, 0x90, 0xC8]},
    "Water":   {"base": 0x06CEBC60, "offsets": [0x4B0, 0x218, 0x90, 0xD8]},
}

# ============================================================
# WORKER
# ============================================================

class StatWorker(threading.Thread):
    def __init__(self, toggles: dict[str, bool]):
        super().__init__(daemon=True)
        self.toggles = toggles
        self.running = True

        pid = get_pid(PROCESS_NAME)
        self.hproc = open_process(pid)
        self.module = get_module_base(pid, PROCESS_NAME)

    def run(self):
        while self.running:
            active = False
            for name, cfg in STATS.items():
                if not self.toggles.get(name, False):
                    continue
                active = True
                try:
                    base = self.module + cfg["base"]
                    addr = read_ptr_chain(self.hproc, base, cfg["offsets"])
                    write_double(self.hproc, addr, GOD_VALUES[name])
                except Exception:
                    pass

            if not active:
                time.sleep(0.05)
            else:
                time.sleep(WRITE_INTERVAL_SEC)

    def stop(self):
        self.running = False
        try:
            kernel32.CloseHandle(self.hproc)
        except Exception:
            pass


# ============================================================
# GUI
# ============================================================

class Menu(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setFixedSize(320, 320)
        self.setStyleSheet(CHEAT_STYLE)

        self.toggles = {k: False for k in STATS}
        self.worker: StatWorker | None = None
        self.drag_pos = QPoint()

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        # Title bar
        title = QWidget(objectName="TitleBar")
        tl = QHBoxLayout(title)
        tl.setContentsMargins(8, 4, 8, 4)

        lbl = QLabel("SurrounDead Cheat  •  INSERT to hide")
        lbl.setObjectName("TitleLabel")
        close = QPushButton("✕")
        close.setFixedWidth(28)
        close.clicked.connect(self.close)

        tl.addWidget(lbl)
        tl.addStretch()
        tl.addWidget(close)
        root.addWidget(title)

        body = QVBoxLayout()
        body.setContentsMargins(10, 10, 10, 10)

        box = QGroupBox("Player Stats (Toggle = God Mode)")
        bl = QVBoxLayout(box)
        for name in STATS:
            cb = QCheckBox(name)
            cb.stateChanged.connect(lambda s, n=name: self._toggle(n, s))
            bl.addWidget(cb)
        body.addWidget(box)

        body.addStretch()

        footer = QLabel("Made by GitHub.com/Cr0mb")
        footer.setAlignment(Qt.AlignCenter)
        footer.setStyleSheet("color: #6B7280; font-size: 10px;")
        body.addWidget(footer)

        root.addLayout(body)

    def _toggle(self, name, state):
        self.toggles[name] = (state == Qt.Checked)

        if any(self.toggles.values()):
            if not self.worker:
                self.worker = StatWorker(self.toggles)
                self.worker.start()
        else:
            if self.worker:
                self.worker.stop()
                self.worker = None

    def toggle_visible(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.raise_()
            self.activateWindow()

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.drag_pos = e.globalPos() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if e.buttons() == Qt.LeftButton:
            self.move(e.globalPos() - self.drag_pos)

    def closeEvent(self, event):
        if self.worker:
            self.worker.stop()
        event.accept()

def main():
    app = QApplication(sys.argv)

    menu = Menu()
    menu.show()

    menu.hotkey_filter = None

    if user32.RegisterHotKey(None, HOTKEY_ID, 0, VK_INSERT):
        menu.hotkey_filter = HotkeyFilter(menu.toggle_visible)
        app.installNativeEventFilter(menu.hotkey_filter)

    try:
        exit_code = app.exec_()
    finally:
        try:
            user32.UnregisterHotKey(None, HOTKEY_ID)
        except Exception:
            pass

    sys.exit(exit_code)



if __name__ == "__main__":
    main()
