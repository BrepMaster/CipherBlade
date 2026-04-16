#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
压缩包密码破解工具 v2.8.1 (修复ZIP传统加密验证误报)
支持格式：ZIP / RAR / 7z
攻击模式：字典、暴力枚举、掩码、自定义 Python 生成器（含模板）
需要安装依赖：
    pip install pyqt5 pyzipper rarfile py7zr
    RAR 破解需要系统安装 unrar 工具并加入 PATH

修复说明（v2.8.1）：
    - 使用 testzip() 方法替代简单读取字节，彻底解决 ZIP 传统加密密码验证误报问题。
    - 保留多编码自动尝试（UTF-8、GBK、Latin-1），完美支持中文密码。
"""

import sys
import os
import itertools
import zipfile
import time
from abc import ABC, abstractmethod
from typing import Iterator, Optional

# 第三方库导入
try:
    import pyzipper
except ImportError:
    pyzipper = None
    print("警告: 未安装 pyzipper，ZIP 破解功能将受限。请执行: pip install pyzipper")

try:
    import rarfile
except ImportError:
    rarfile = None
    print("警告: 未安装 rarfile，RAR 破解功能不可用。请执行: pip install rarfile")

try:
    import py7zr
except ImportError:
    py7zr = None
    print("警告: 未安装 py7zr，7z 破解功能不可用。请执行: pip install py7zr")

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QComboBox,
    QStackedWidget, QSpinBox, QTextEdit, QProgressBar, QMessageBox,
    QGroupBox, QFormLayout, QMenuBar, QAction, QDialog, QTextBrowser,
    QDesktopWidget, QCheckBox
)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont


# ==================== 密码生成器模块 ====================
class PasswordGenerator(ABC):
    """密码生成器抽象基类"""
    @abstractmethod
    def __iter__(self) -> Iterator[str]:
        pass

    @abstractmethod
    def total_count(self) -> Optional[int]:
        """返回密码总数，若无法估算则返回 None"""
        pass


class DictionaryGenerator(PasswordGenerator):
    """字典攻击生成器"""
    def __init__(self, dict_path: str):
        self.dict_path = dict_path
        self._count = None

    def __iter__(self):
        with open(self.dict_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    yield line

    def total_count(self):
        if self._count is None:
            try:
                with open(self.dict_path, 'rb') as f:
                    self._count = sum(1 for _ in f)
            except:
                self._count = 0
        return self._count


class BruteForceGenerator(PasswordGenerator):
    """暴力枚举生成器"""
    def __init__(self, charset: str, min_len: int, max_len: int):
        self.charset = charset
        self.min_len = min_len
        self.max_len = max_len

    def __iter__(self):
        for length in range(self.min_len, self.max_len + 1):
            for combo in itertools.product(self.charset, repeat=length):
                yield ''.join(combo)

    def total_count(self):
        total = 0
        for l in range(self.min_len, self.max_len + 1):
            total += len(self.charset) ** l
        return total


class MaskGenerator(PasswordGenerator):
    """掩码攻击生成器"""
    PLACEHOLDERS = {
        '?l': 'abcdefghijklmnopqrstuvwxyz',
        '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        '?d': '0123456789',
        '?s': '!@#$%^&*()_+-=[]{}|;:,.<>?/~',
        '?a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~'
    }

    def __init__(self, mask: str, custom_placeholders: dict = None):
        self.mask = mask
        self.charsets = self.PLACEHOLDERS.copy()
        if custom_placeholders:
            self.charsets.update(custom_placeholders)
        self._validate_mask()
        self._tokens = self._parse_mask()

    def _validate_mask(self):
        import re
        tokens = re.findall(r'\?[ludsac]|\?\{[^}]+\}|.', self.mask)
        for token in tokens:
            if token.startswith('?') and token not in self.charsets:
                raise ValueError(f"未知掩码占位符: {token}")

    def _parse_mask(self):
        import re
        tokens = re.findall(r'\?[ludsac]|\?\{[^}]+\}|.', self.mask)
        components = []
        for token in tokens:
            if token.startswith('?'):
                components.append(list(self.charsets[token]))
            else:
                components.append([token])
        return components

    def __iter__(self):
        for combo in itertools.product(*self._tokens):
            yield ''.join(combo)

    def total_count(self):
        count = 1
        for comp in self._tokens:
            count *= len(comp)
        return count


class CustomGenerator(PasswordGenerator):
    """自定义代码生成器"""
    def __init__(self, code: str):
        self.code = code
        self._gen_func = None
        self._total_func = None
        self._compile()

    def _compile(self):
        namespace = {}
        safe_builtins = {
            'range': range, 'len': len, 'enumerate': enumerate,
            'list': list, 'tuple': tuple, 'dict': dict, 'set': set,
            'str': str, 'int': int, 'float': float, 'bool': bool,
            'print': print, 'iter': iter, 'next': next,
            '__import__': __import__
        }
        exec(self.code, {"__builtins__": safe_builtins}, namespace)
        if 'generator' not in namespace:
            raise ValueError("代码中必须定义一个名为 generator 的函数，且返回可迭代对象")
        self._gen_func = namespace['generator']
        self._total_func = namespace.get('total', None)

    def __iter__(self):
        return iter(self._gen_func())

    def total_count(self):
        if self._total_func:
            try:
                return self._total_func()
            except:
                return None
        return None


# ==================== 压缩包处理器模块 ====================
class ArchiveHandler:
    """处理器工厂"""
    @staticmethod
    def get_handler(file_path: str):
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.zip':
            return ZipHandler(file_path)
        elif ext == '.rar':
            return RarHandler(file_path)
        elif ext == '.7z':
            return SevenZipHandler(file_path)
        else:
            raise ValueError(f"不支持的压缩格式: {ext}")


class BaseHandler:
    def __init__(self, path):
        self.path = path
        self._first_file = None

    def is_encrypted(self) -> bool:
        raise NotImplementedError

    def test_password(self, password: str) -> bool:
        raise NotImplementedError

    def first_filename(self) -> str:
        raise NotImplementedError


class ZipHandler(BaseHandler):
    """
    修复后的 ZIP 处理器：
    - 自动检测 AES 与传统 ZipCrypto 加密
    - 依次尝试 UTF-8、GBK、Latin-1 编码
    - 使用 testzip() 方法准确验证密码，杜绝误报
    """
    def __init__(self, path):
        super().__init__(path)
        if pyzipper is None:
            raise ImportError("请安装 pyzipper: pip install pyzipper")
        if self._is_split_volume():
            raise ValueError("检测到分卷ZIP文件，请先使用 copy /b 命令合并后再尝试。")
        self._is_aes = self._check_aes_encryption()

    def _is_split_volume(self):
        base = os.path.basename(self.path)
        return '.zip.' in base and any(p.isdigit() for p in base.split('.zip.')[1:])

    def _check_aes_encryption(self):
        """检查 ZIP 是否使用 AES 加密（通过压缩方法 99 判断）"""
        try:
            with zipfile.ZipFile(self.path, 'r') as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:  # 加密标志
                        # AES 加密的压缩方法为 99 (WinZip AES)
                        if info.compress_type == 99:
                            return True
                return False
        except:
            # 无法读取则保守假设为传统加密
            return False

    def is_encrypted(self):
        try:
            with zipfile.ZipFile(self.path, 'r') as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        return True
                return False
        except:
            return True

    def test_password(self, password: str):
        """
        增强版密码验证：使用 testzip() 方法校验 CRC32，
        完美解决传统 ZipCrypto 误报问题。
        """
        encodings = ['utf-8', 'gbk', 'latin-1']

        for enc in encodings:
            try:
                pwd_bytes = password.encode(enc)
            except UnicodeEncodeError:
                continue

            try:
                if self._is_aes:
                    with pyzipper.AESZipFile(self.path, 'r') as zf:
                        zf.setpassword(pwd_bytes)
                        # testzip() 返回第一个校验失败的文件名，成功返回 None
                        bad_file = zf.testzip()
                        if bad_file is None:
                            return True
                else:
                    with pyzipper.ZipFile(self.path, 'r') as zf:
                        zf.setpassword(pwd_bytes)
                        bad_file = zf.testzip()
                        if bad_file is None:
                            return True
            except RuntimeError:
                # 密码错误时 testzip() 也可能抛出 RuntimeError
                continue
            except Exception as e:
                # 其他异常（如文件损坏）直接抛出，避免隐藏真正错误
                raise e

        # 所有编码尝试完毕均失败
        return False

    def first_filename(self):
        with zipfile.ZipFile(self.path, 'r') as zf:
            return zf.namelist()[0]


class RarHandler(BaseHandler):
    def __init__(self, path):
        super().__init__(path)
        if rarfile is None:
            raise ImportError("请安装 rarfile: pip install rarfile")
        self._setup_unrar_tool()

    def _setup_unrar_tool(self):
        """配置 rarfile 使用正确的 unrar 工具"""
        if rarfile.UNRAR_TOOL and os.path.exists(rarfile.UNRAR_TOOL):
            return

        unrar_path = self._find_unrar_tool()
        if unrar_path:
            rarfile.UNRAR_TOOL = unrar_path
            if hasattr(rarfile, 'TOOL_CONFIG'):
                rarfile.TOOL_CONFIG = {'unrar': unrar_path}
            return

        import shutil
        system_unrar = shutil.which('unrar') or shutil.which('UnRAR.exe')
        if system_unrar:
            rarfile.UNRAR_TOOL = system_unrar
            if hasattr(rarfile, 'TOOL_CONFIG'):
                rarfile.TOOL_CONFIG = {'unrar': system_unrar}
            return

        raise EnvironmentError(
            "未找到 unrar 工具。\n"
            "请下载 UnRAR.exe 并放置在以下任一位置：\n"
            "1. 本程序所在目录\n"
            "2. 系统 PATH 环境变量中的目录\n"
            "下载地址：https://www.rarlab.com/rar_add.htm"
        )

    def _find_unrar_tool(self):
        """在常见位置查找 unrar 可执行文件"""
        if sys.platform == 'win32':
            candidates = [
                os.path.join(os.getcwd(), "UnRAR.exe"),
                r"C:\Program Files\WinRAR\UnRAR.exe",
                r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
            ]
            import shutil
            path_unrar = shutil.which("UnRAR.exe")
            if path_unrar:
                candidates.insert(0, path_unrar)
        else:
            candidates = [
                "/usr/bin/unrar",
                "/usr/local/bin/unrar",
                "/opt/bin/unrar",
                os.path.join(os.getcwd(), "unrar"),
            ]
        for p in candidates:
            if os.path.exists(p):
                return p
        return None

    def is_encrypted(self):
        try:
            with rarfile.RarFile(self.path, 'r') as rf:
                return rf.needs_password()
        except:
            return True

    def test_password(self, password: str):
        try:
            with rarfile.RarFile(self.path, 'r') as rf:
                rf.setpassword(password)
                rf.testrar()
                return True
        except Exception as e:
            err_msg = str(e).lower()
            if "wrong password" in err_msg or "bad password" in err_msg:
                return False
            elif "read enough data" in err_msg or "rarreaderror" in err_msg:
                # 忽略分卷缺失错误，继续尝试下一个密码
                return False
            else:
                return False

    def first_filename(self):
        try:
            with rarfile.RarFile(self.path, 'r') as rf:
                return rf.namelist()[0]
        except:
            return "<无法读取文件名>"


class SevenZipHandler(BaseHandler):
    def __init__(self, path):
        super().__init__(path)
        if py7zr is None:
            raise ImportError("请安装 py7zr: pip install py7zr")

    def is_encrypted(self):
        try:
            with py7zr.SevenZipFile(self.path, 'r') as szf:
                return szf.needs_password()
        except:
            return True

    def test_password(self, password: str):
        try:
            with py7zr.SevenZipFile(self.path, 'r', password=password) as szf:
                szf.testzip()
                return True
        except py7zr.Bad7zFile:
            return False
        except Exception as e:
            raise e

    def first_filename(self):
        with py7zr.SevenZipFile(self.path, 'r') as szf:
            return szf.getnames()[0]


# ==================== 破解工作线程 ====================
class CrackWorker(QThread):
    progress = pyqtSignal(int, int, str)
    status = pyqtSignal(str)
    found = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, archive_path: str, generator: PasswordGenerator, update_interval: int = 1):
        super().__init__()
        self.archive_path = archive_path
        self.generator = generator
        self.update_interval = max(1, update_interval)
        self._is_running = True

    def run(self):
        try:
            handler = ArchiveHandler.get_handler(self.archive_path)
            if not handler.is_encrypted():
                self.status.emit("压缩包未加密，无需破解")
                self.finished.emit(True, "无需密码")
                return

            total = self.generator.total_count()
            self.status.emit(f"开始破解，预计密码数: {total if total else '未知'} (刷新间隔: {self.update_interval})")

            count = 0
            start_time = time.time()

            for pwd in self.generator:
                if not self._is_running:
                    self.status.emit("用户中止")
                    self.finished.emit(False, "已中止")
                    return

                try:
                    if handler.test_password(pwd):
                        self.found.emit(pwd)
                        self.finished.emit(True, f"密码找到: {pwd}")
                        return
                except RuntimeError as e:
                    self.error.emit(str(e))
                    self.finished.emit(False, f"致命错误: {e}")
                    return
                except Exception as e:
                    self.status.emit(f"测试密码时发生临时错误: {e}，继续尝试...")
                    continue

                count += 1

                if count % self.update_interval == 0 or count == total:
                    now = time.time()
                    if total:
                        elapsed = now - start_time
                        speed = count / elapsed if elapsed > 0 else 0
                        remaining = (total - count) / speed if speed > 0 else 0
                        status_text = f"{count}/{total} | 速度: {speed:.1f} pwd/s | 剩余: {self._format_time(remaining)}"
                        self.progress.emit(count, total, status_text)
                    else:
                        self.progress.emit(count, 0, f"已尝试: {count}")

            self.finished.emit(False, "密码未找到")

        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, f"初始化失败: {e}")

    def _format_time(self, seconds):
        if seconds < 0:
            return "计算中..."
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        if h > 0:
            return f"{h}h{m}m{s}s"
        elif m > 0:
            return f"{m}m{s}s"
        else:
            return f"{s}s"

    def stop(self):
        self._is_running = False


# ==================== 主界面 ====================
class CrackGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("压缩包密码破解工具")
        self.setMinimumSize(780, 720)
        self.setStyleSheet(self._get_stylesheet())
        self._create_menu_bar()

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # === 文件选择 ===
        file_group = QGroupBox("目标文件")
        file_layout = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("选择压缩包 (.zip, .rar, .7z)")
        self.browse_btn = QPushButton("浏览")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_edit)
        file_layout.addWidget(self.browse_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # === 攻击模式 ===
        mode_group = QGroupBox("攻击模式")
        mode_layout = QVBoxLayout()
        mode_select_layout = QHBoxLayout()
        mode_select_layout.addWidget(QLabel("模式:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["字典攻击", "暴力枚举", "掩码攻击", "自定义生成器"])
        self.mode_combo.currentIndexChanged.connect(self.on_mode_changed)
        mode_select_layout.addWidget(self.mode_combo)
        mode_select_layout.addStretch()
        mode_layout.addLayout(mode_select_layout)

        self.param_stack = QStackedWidget()
        self.param_stack.addWidget(self._create_dict_panel())
        self.param_stack.addWidget(self._create_bruteforce_panel())
        self.param_stack.addWidget(self._create_mask_panel())
        self.param_stack.addWidget(self._create_custom_panel())
        mode_layout.addWidget(self.param_stack)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)

        # === 性能设置 ===
        perf_group = QGroupBox("性能设置")
        perf_layout = QHBoxLayout()
        self.perf_check = QCheckBox("启用性能模式（减少界面刷新）")
        self.perf_check.setChecked(False)
        self.perf_check.toggled.connect(self.on_perf_toggled)
        perf_layout.addWidget(self.perf_check)
        perf_layout.addWidget(QLabel("刷新间隔:"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1, 10000)
        self.interval_spin.setValue(100)
        self.interval_spin.setSuffix(" 次")
        self.interval_spin.setEnabled(False)
        self.interval_spin.setToolTip("每尝试多少次密码更新一次界面，数值越大速度越快但反馈越少")
        perf_layout.addWidget(self.interval_spin)
        perf_layout.addStretch()
        perf_group.setLayout(perf_layout)
        layout.addWidget(perf_group)

        # === 控制按钮 ===
        ctrl_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ 开始破解")
        self.start_btn.clicked.connect(self.start_crack)
        self.stop_btn = QPushButton("■ 停止")
        self.stop_btn.clicked.connect(self.stop_crack)
        self.stop_btn.setEnabled(False)
        ctrl_layout.addWidget(self.start_btn)
        ctrl_layout.addWidget(self.stop_btn)
        ctrl_layout.addStretch()
        layout.addLayout(ctrl_layout)

        # === 进度条 ===
        self.progress_bar = QProgressBar()
        self.progress_bar.setFormat("就绪")
        layout.addWidget(self.progress_bar)

        # === 日志输出 ===
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 10))
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        self.center()
        self.on_mode_changed(0)

    def on_perf_toggled(self, checked):
        self.interval_spin.setEnabled(checked)

    def _get_stylesheet(self):
        return """
            QMainWindow { background-color: #f5f5f5; }
            QGroupBox {
                font-weight: bold; border: 1px solid #cccccc;
                border-radius: 6px; margin-top: 12px; padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin; left: 12px;
                padding: 0 6px; color: #333333;
            }
            QPushButton {
                background-color: #4CAF50; color: white; border: none;
                padding: 8px 16px; border-radius: 4px; font-weight: bold;
            }
            QPushButton:hover { background-color: #45a049; }
            QPushButton:pressed { background-color: #3d8b40; }
            QPushButton:disabled { background-color: #cccccc; }
            QLineEdit, QSpinBox, QComboBox, QTextEdit {
                border: 1px solid #cccccc; border-radius: 4px; padding: 6px;
                selection-background-color: #a6c8ff; background-color: white;
            }
            QProgressBar {
                border: 1px solid #cccccc; border-radius: 5px;
                text-align: center; background-color: white;
            }
            QProgressBar::chunk {
                background-color: #4CAF50; border-radius: 4px;
            }
            QTextEdit {
                background-color: #ffffff;
                font-family: Consolas, monospace;
            }
            QLabel { color: #333333; }
        """

    def _create_menu_bar(self):
        menubar = self.menuBar()
        help_menu = menubar.addMenu("帮助")
        usage_action = QAction("使用说明", self)
        usage_action.triggered.connect(self.show_usage)
        help_menu.addAction(usage_action)
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def _create_dict_panel(self):
        panel = QWidget()
        layout = QFormLayout(panel)
        self.dict_path_edit = QLineEdit()
        self.dict_browse_btn = QPushButton("浏览")
        self.dict_browse_btn.clicked.connect(self.browse_dict)
        hl = QHBoxLayout()
        hl.addWidget(self.dict_path_edit)
        hl.addWidget(self.dict_browse_btn)
        layout.addRow("字典文件:", hl)
        layout.addRow("", QLabel("每行一个密码，支持 UTF-8 编码"))
        return panel

    def _create_bruteforce_panel(self):
        panel = QWidget()
        layout = QFormLayout(panel)
        self.charset_edit = QLineEdit("abcdefghijklmnopqrstuvwxyz0123456789")
        layout.addRow("字符集:", self.charset_edit)
        len_layout = QHBoxLayout()
        self.min_len_spin = QSpinBox()
        self.min_len_spin.setRange(1, 20)
        self.min_len_spin.setValue(1)
        self.max_len_spin = QSpinBox()
        self.max_len_spin.setRange(1, 20)
        self.max_len_spin.setValue(6)
        len_layout.addWidget(QLabel("最小长度:"))
        len_layout.addWidget(self.min_len_spin)
        len_layout.addWidget(QLabel("最大长度:"))
        len_layout.addWidget(self.max_len_spin)
        layout.addRow("长度范围:", len_layout)
        layout.addRow("", QLabel("注意：长度过长会导致组合数爆炸式增长"))
        return panel

    def _create_mask_panel(self):
        panel = QWidget()
        layout = QFormLayout(panel)
        self.mask_edit = QLineEdit("?l?l?l?d?d?d")
        layout.addRow("掩码:", self.mask_edit)
        help_label = QLabel("占位符: ?l小写 ?u大写 ?d数字 ?s特殊 ?a全部")
        help_label.setStyleSheet("color: #666666; font-size: 9pt;")
        layout.addRow("", help_label)
        return panel

    def _create_custom_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        warning = QLabel("<font color='red'><b>⚠️ 安全警告：自定义代码将直接执行，请勿运行来源不明的代码！</b></font>")
        layout.addWidget(warning)
        help_label = QLabel("编写 Python 函数 generator()，返回密码的可迭代对象。可选定义 total() 返回总数。")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        self.custom_code_edit = QTextEdit()
        self.custom_code_edit.setFont(QFont("Consolas", 10))
        default_code = '''# 自定义密码生成器模板
def generator():
    from datetime import date, timedelta
    letters = [('A', 'a'), ('B', 'b'), ('C', 'c')]
    import itertools
    prefixes = [''.join(p) for p in itertools.product(*letters)]
    start = date(2024, 1, 1)
    end = date(2025, 12, 31)
    delta = timedelta(days=1)
    current = start
    while current <= end:
        date_str1 = current.strftime('%Y%m%d')
        date_str2 = f"{current.year}{current.month}{current.day}"
        for prefix in prefixes:
            yield prefix + date_str1
            yield prefix + date_str2
        current += delta

def total():
    from datetime import date
    days = (date(2025, 12, 31) - date(2024, 1, 1)).days + 1
    return days * 8 * 2
'''
        self.custom_code_edit.setPlainText(default_code)
        reset_btn = QPushButton("重置为默认模板")
        reset_btn.clicked.connect(lambda: self.custom_code_edit.setPlainText(default_code))
        layout.addWidget(self.custom_code_edit)
        layout.addWidget(reset_btn)
        return panel

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择压缩包", "",
            "压缩文件 (*.zip *.rar *.7z);;所有文件 (*.*)"
        )
        if path:
            self.file_edit.setText(path)

    def browse_dict(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if path:
            self.dict_path_edit.setText(path)

    def on_mode_changed(self, idx):
        self.param_stack.setCurrentIndex(idx)

    def start_crack(self):
        archive = self.file_edit.text().strip()
        if not archive:
            QMessageBox.warning(self, "警告", "请选择压缩包文件")
            return
        if not os.path.exists(archive):
            QMessageBox.warning(self, "警告", "文件不存在")
            return

        try:
            mode = self.mode_combo.currentIndex()
            if mode == 0:
                dict_path = self.dict_path_edit.text().strip()
                if not dict_path:
                    QMessageBox.warning(self, "警告", "请选择字典文件")
                    return
                generator = DictionaryGenerator(dict_path)
            elif mode == 1:
                charset = self.charset_edit.text().strip()
                if not charset:
                    QMessageBox.warning(self, "警告", "字符集不能为空")
                    return
                min_len = self.min_len_spin.value()
                max_len = self.max_len_spin.value()
                if min_len > max_len:
                    QMessageBox.warning(self, "警告", "最小长度不能大于最大长度")
                    return
                generator = BruteForceGenerator(charset, min_len, max_len)
            elif mode == 2:
                mask = self.mask_edit.text().strip()
                if not mask:
                    QMessageBox.warning(self, "警告", "掩码不能为空")
                    return
                generator = MaskGenerator(mask)
            else:
                code = self.custom_code_edit.toPlainText().strip()
                if not code:
                    QMessageBox.warning(self, "警告", "请输入自定义生成器代码")
                    return
                generator = CustomGenerator(code)
        except Exception as e:
            QMessageBox.critical(self, "参数错误", f"初始化生成器失败：{e}")
            return

        if self.perf_check.isChecked():
            update_interval = self.interval_spin.value()
        else:
            update_interval = 1

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.log_text.clear()
        self.progress_bar.reset()
        self.progress_bar.setFormat("0%")

        self.worker = CrackWorker(archive, generator, update_interval)
        self.worker.progress.connect(self.on_progress)
        self.worker.status.connect(self.on_status)
        self.worker.found.connect(self.on_found)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def stop_crack(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.stop_btn.setEnabled(False)

    def on_progress(self, current, total, status_text):
        if total and total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)
            percent = current / total * 100
            self.progress_bar.setFormat(f"{percent:.1f}% - {status_text}")
        else:
            self.progress_bar.setMaximum(0)
            self.progress_bar.setFormat(status_text)

    def on_status(self, msg):
        self.log_text.append(f'<font color="#0066cc">[状态] {msg}</font>')

    def on_found(self, pwd):
        self.log_text.append(f'<font color="#ff6600"><b>🎉 找到密码: {pwd}</b></font>')

    def on_finished(self, success, msg):
        self.log_text.append(f'<font color="#333333">[完成] {msg}</font>')
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setFormat("完成" if success else "中止")

    def on_error(self, err):
        self.log_text.append(f'<font color="#cc0000"><b>❌ 错误: {err}</b></font>')
        QMessageBox.critical(self, "错误", err)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setFormat("错误")

    def show_usage(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("使用说明")
        dialog.resize(600, 480)
        layout = QVBoxLayout(dialog)
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setHtml("""
        <h2>📖 压缩包密码破解工具 使用说明 (修复版 v2.8.1)</h2>
        <h3>1. 选择目标文件</h3>
        <p>支持格式：<b>.zip</b>、<b>.rar</b>、<b>.7z</b>。<br>
        <font color="red">本次修复：使用 testzip() 方法彻底解决 ZIP 传统加密密码验证误报问题，并保留多编码自动尝试。</font></p>
        <h3>2. 攻击模式</h3>
        <ul>
        <li><b>字典攻击</b>：从文本文件读取密码。</li>
        <li><b>暴力枚举</b>：指定字符集和长度范围。</li>
        <li><b>掩码攻击</b>：使用占位符，如 <code>?l?l?l?d?d?d</code>。</li>
        <li><b>自定义生成器</b>：编写 Python 代码动态生成密码。</li>
        </ul>
        <h3>3. 性能设置</h3>
        <p>启用“性能模式”可减少界面刷新频率，提升破解速度。</p>
        <h3>4. 免责声明</h3>
        <p>本工具仅供合法授权的安全测试、数据恢复及教育用途。</p>
        """)
        layout.addWidget(text_browser)
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        dialog.exec_()

    def show_about(self):
        QMessageBox.about(self, "关于",
            "<h3>压缩包密码破解工具 v2.8.1 (修复版)</h3>"
            "<p>基于 PyQt5 开发，支持 ZIP / RAR / 7z 格式。</p>"
            "<p>密码生成支持字典、暴力、掩码及自定义 Python 代码。</p>"
            "<p><b>修复：</b>使用 testzip() 彻底解决 ZIP 传统加密误报问题。</p>"
            "<p>开源协议：MIT</p>"
            "<p>⚠️ 仅供合法授权使用</p>")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    gui = CrackGUI()
    gui.show()
    sys.exit(app.exec_())