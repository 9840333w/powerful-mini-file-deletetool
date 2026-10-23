# -*- coding: utf-8 -*-
"""
强力删除（Force Delete）
=========================
轻量级 Windows 顽固文件 / 文件夹强制删除 + 通用注册表残留清理工具。

【文件删除】五级策略逐级升级，确保“无论如何都要删掉”：
  1. 清除 只读 / 系统 / 隐藏 属性（attrib）
  2. 获取所有权并授予完全控制权限（takeown + icacls，使用 SID 兼容中英文系统）
  3. 通过 Restart Manager（系统原生 API）找到并结束占用文件的进程 / 服务
  4. 依次尝试：直接删除 → \\\\?\\ 前缀删除（超长路径 / 保留名）→ 改名后删除
  5. 仍然失败时，通过 MoveFileEx 安排“下次重启自动删除”

【注册表残留清理】按关键词通用扫描（不只针对某一家软件）：
  - 扫描范围：卸载信息、启动项(Run/RunOnce)、系统服务、软件厂商键，
    可选深度扫描 HKLM/HKCU\\SOFTWARE 全树（键名匹配→整键项；值匹配→仅值项）
  - 删除前自动 reg export 备份 .reg（可双击还原），并内置系统关键键黑名单
  - 删除失败自动夺取注册表所有权（SetNamedSecurityInfo）后重试

说明：
  - 启动时自动申请管理员权限（UAC 提权），这是强制删除的前提；
  - 符号链接 / 目录联接（junction）只删除链接本身，不删除其指向的真实内容；
  - 支持拖拽文件 / 文件夹到窗口（内置 tkinterdnd2，缺失时自动回退为按钮添加）。
"""

import os
import re
import sys
import stat
import ctypes
import shutil
import random
import string
import subprocess
import threading
import queue
import time
import winreg
from ctypes import wintypes

APP_TITLE = "强力删除"
MOVEFILE_DELAY_UNTIL_REBOOT = 0x4          # MoveFileExW 标志：重启后删除
FILE_ATTRIBUTE_REPARSE_POINT = 0x400       # 重解析点（符号链接 / junction）
CREATE_NO_WINDOW = 0x08000000              # 子进程不弹黑色控制台窗口

kernel32 = ctypes.windll.kernel32


# ----------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------
def run_hidden(cmd, timeout=300):
    """静默执行控制台命令（attrib / takeown / icacls / reg），返回 CompletedProcess。"""
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              startupinfo=si, creationflags=CREATE_NO_WINDOW,
                              timeout=timeout)
    except Exception:
        return None


def is_admin():
    """判断当前进程是否拥有管理员权限。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """以管理员身份重新启动自身（触发 UAC）。返回 True 表示已成功发起重启。"""
    if getattr(sys, "frozen", False):
        exe = sys.executable
        args = " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        exe = sys.executable
        args = " ".join([f'"{os.path.abspath(__file__)}"'] +
                        [f'"{a}"' for a in sys.argv[1:]])
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
    return ret > 32   # <=32 表示用户取消了 UAC 或出错


def longpath(p):
    """转换为 \\\\?\\ 前缀路径，用于突破 260 字符限制 / 保留设备名（CON、NUL 等）。"""
    if p.startswith("\\\\?\\"):
        return p
    p = os.path.abspath(p)
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p.lstrip("\\")
    return "\\\\?\\" + p


def path_exists(p):
    return os.path.lexists(p) or os.path.lexists(longpath(p))


def is_reparse_point(p):
    """是否为符号链接 / junction。此类对象只删除链接本身，防止误删链接目标的内容。"""
    try:
        attrs = os.stat(p, follow_symlinks=False).st_file_attributes
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return os.path.islink(p)


# ----------------------------------------------------------------------
# 文件删除 步骤 1 & 2：属性清除 + 所有权 / 权限夺取
# ----------------------------------------------------------------------
def clear_attributes(path):
    """清除 只读 / 系统 / 隐藏 属性（含目录内全部子项）。"""
    run_hidden(["attrib", "-r", "-s", "-h", path])
    if os.path.isdir(path):
        run_hidden(["attrib", "-r", "-s", "-h", path, "/s", "/d"])
    else:
        try:
            os.chmod(path, stat.S_IWRITE)
        except Exception:
            pass


def grant_access(path):
    """
    夺取所有权并授予完全控制权限。
    S-1-5-32-544 = Administrators 组，S-1-5-18 = SYSTEM。
    使用 SID 而非组名，保证在中文 / 英文系统上都生效。
    """
    if os.path.isdir(path):
        run_hidden(["takeown", "/f", path, "/a", "/r", "/d", "y"])
        run_hidden(["icacls", path, "/grant",
                    "*S-1-5-32-544:F", "*S-1-5-18:F", "/t", "/c", "/l", "/q"])
    else:
        run_hidden(["takeown", "/f", path, "/a"])
        run_hidden(["icacls", path, "/grant",
                    "*S-1-5-32-544:F", "*S-1-5-18:F", "/c", "/l", "/q"])


# ----------------------------------------------------------------------
# 文件删除 步骤 3：Restart Manager —— 查找并结束占用进程
# ----------------------------------------------------------------------
CCH_RM_SESSION_KEY = 32
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63
RM_FORCE_SHUTDOWN = 0x1


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD),
                ("ProcessStartTime", wintypes.FILETIME)]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("Process", RM_UNIQUE_PROCESS),
                ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
                ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
                ("ApplicationType", wintypes.DWORD),
                ("AppStatus", wintypes.ULONG),
                ("TSSessionId", wintypes.DWORD),
                ("bRestartable", wintypes.BOOL)]


def collect_lock_targets(path, limit=1000):
    """收集要注册给 RM 的文件路径：目录需展开为其内部文件（RM 只接受文件）。"""
    targets = [path]
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for f in files:
                targets.append(os.path.join(root, f))
                if len(targets) >= limit:
                    return targets
    return targets


def kill_locking_processes(path, log):
    """
    通过 Restart Manager 找到占用 path 的进程并强制结束。
    返回被结束的进程名列表。若资源管理器(explorer)被结束则自动重启之。
    """
    try:
        rm = ctypes.WinDLL("rstrtmgr")
    except Exception:
        return []

    targets = collect_lock_targets(path)
    session = wintypes.DWORD(0)
    key = (wintypes.WCHAR * (CCH_RM_SESSION_KEY + 1))()
    if rm.RmStartSession(ctypes.byref(session), 0, key) != 0:
        return []

    killed = []
    try:
        arr = (wintypes.LPCWSTR * len(targets))(*targets)
        if rm.RmRegisterResources(session, len(targets), arr, 0, None, 0, None) != 0:
            return []

        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reasons = wintypes.DWORD(0)
        # 第一次调用获取需要的缓冲区大小
        rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count),
                     None, ctypes.byref(reasons))
        if needed.value == 0:
            return []

        infos = (RM_PROCESS_INFO * needed.value)()
        count = needed
        if rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count),
                        infos, ctypes.byref(reasons)) != 0:
            return []

        self_pid = os.getpid()
        need_shutdown = False
        explorer_killed = False
        for i in range(count.value):
            pid = infos[i].Process.dwProcessId
            name = infos[i].strAppName or f"PID {pid}"
            if pid == self_pid:
                continue                      # 不杀自己（极端情况：删除工具自身）
            need_shutdown = True
            killed.append(name)
            if name.lower() == "explorer.exe":
                explorer_killed = True

        if need_shutdown:
            rm.RmShutdown(session, RM_FORCE_SHUTDOWN, None)
            time.sleep(1.0)                   # 等待句柄真正释放
            if explorer_killed:               # 桌面被结束则自动拉回
                subprocess.Popen(["explorer.exe"])
        return killed
    finally:
        rm.RmEndSession(session)


# ----------------------------------------------------------------------
# 文件删除 步骤 4 & 5：多策略删除 + 重启后删除兜底
# ----------------------------------------------------------------------
def _rmtree(path):
    """递归删除目录，遇到只读文件自动去掉只读后重试。"""
    def onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: onerror(f, p, e))
    else:
        shutil.rmtree(path, onerror=onerror)


def schedule_delete_on_reboot(path):
    """注册“下次重启时删除”（PendingFileRenameOperations，系统级兜底）。"""
    return bool(kernel32.MoveFileExW(path, None, MOVEFILE_DELAY_UNTIL_REBOOT))


def force_delete_path(path, log, opts):
    """
    强制删除单个路径。
    返回 (是否视为成功, 是否安排了重启后删除)。
    """
    if not path_exists(path):
        log(f"[跳过] 路径不存在：{path}")
        return True, False

    reparse = is_reparse_point(path) or is_reparse_point(longpath(path))
    is_dir = (os.path.isdir(path) or os.path.isdir(longpath(path))) and not reparse
    kind = "链接" if reparse else ("文件夹" if is_dir else "文件")
    log(f"[处理] {kind}：{path}")

    # —— 逐级升级的前置处理 ——
    clear_attributes(path)
    if opts.get("grant"):
        grant_access(path)
    if opts.get("unlock"):
        killed = kill_locking_processes(path, log)
        if killed:
            names = ", ".join(sorted(set(killed))[:10])
            log(f"  → 已结束占用进程：{names}")

    def do_delete(p):
        """删除指定路径，并在结束后校验是否真正删干净（rmtree 可能静默残留）。"""
        if reparse:                       # 链接：只删链接本身
            try:
                os.rmdir(p)               # junction / 目录符号链接
            except OSError:
                os.remove(p)              # 文件符号链接
        elif is_dir:
            _rmtree(p)
        else:
            os.remove(p)
        if path_exists(p):
            raise OSError("删除后仍有残留")

    def rename_then_delete():
        """改名后删除：对付仍持有句柄但允许改名的占用。"""
        parent = os.path.dirname(path)
        newname = os.path.join(parent, "__del_" +
                               "".join(random.choices(
                                   string.ascii_lowercase + string.digits, k=8)))
        os.rename(path, newname)
        do_delete(newname)

    # 三级删除策略，逐级尝试，每级都校验结果
    attempts = [
        lambda: do_delete(path),                # 1. 直接删除
        lambda: do_delete(longpath(path)),      # 2. \\?\ 前缀（超长路径/保留名/尾随点）
        rename_then_delete,                     # 3. 改名后删除（绕句柄占用）
    ]
    last_err = None
    for attempt in attempts:
        try:
            attempt()
        except Exception as e:
            last_err = e
        if not path_exists(path):
            log("[成功] 已彻底删除")
            return True, False

    # —— 终极兜底：安排重启后删除 ——
    if opts.get("reboot") and schedule_delete_on_reboot(path):
        log("[计划] 占用过深，已安排【重启电脑后自动删除】")
        return True, True
    log(f"[失败] {last_err if last_err else '未知错误'}")
    return False, False


# ======================================================================
# 注册表残留清理模块
# ======================================================================
REG_ROOTS = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKU": winreg.HKEY_USERS,
}

# SetNamedSecurityInfo 使用的根键名映射
REG_MACHINE_NAME = {
    "HKLM": "MACHINE", "HKCU": "CURRENT_USER",
    "HKCR": "CLASSES_ROOT", "HKU": "USERS",
}

# 卸载信息（64 位 / 32 位 / 当前用户）
REG_UNINSTALL_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

# 启动项
REG_RUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]

REG_SERVICES_KEY = ("HKLM", r"SYSTEM\CurrentControlSet\Services")

# 软件厂商键（快速模式：顶层键名匹配）
REG_VENDOR_PARENTS = [
    ("HKLM", r"SOFTWARE"),
    ("HKLM", r"SOFTWARE\Wow6432Node"),
    ("HKCU", r"SOFTWARE"),
    ("HKCU", r"SOFTWARE\Wow6432Node"),
    ("HKCR", r""),
]

# 深度扫描根
REG_DEEP_ROOTS = [("HKLM", r"SOFTWARE"), ("HKCU", r"SOFTWARE")]

# 系统关键键黑名单：无论关键词是什么，这些键永远不会被列为删除项
REG_DENYLIST = {
    "hklm", "hkcu", "hkcr", "hku",
    r"hklm\software", r"hkcu\software",
    r"hklm\software\wow6432node", r"hkcu\software\wow6432node",
    r"hklm\software\classes", r"hklm\security", r"hklm\sam", r"hklm\hardware",
    r"hklm\software\microsoft", r"hkcu\software\microsoft",
    r"hklm\software\microsoft\windows",
    r"hklm\software\microsoft\windows\currentversion",
    r"hklm\software\microsoft\windows nt\currentversion",
    r"hklm\software\wow6432node\microsoft",
    r"hklm\software\wow6432node\microsoft\windows",
    r"hklm\software\wow6432node\microsoft\windows\currentversion",
    r"hkcu\software\microsoft\windows",
    r"hkcu\software\microsoft\windows\currentversion",
    r"hklm\system", r"hklm\system\currentcontrolset",
    r"hklm\system\currentcontrolset\control",
    r"hklm\system\currentcontrolset\services",
}

REG_ITEM_CAP = 800        # 单次扫描结果上限
REG_VISIT_CAP = 300000    # 深度扫描遍历键数上限


def parse_keywords(text):
    """解析关键词输入：支持空格 / 逗号 / 分号分隔，自动去重、转小写。"""
    parts = re.split(r"[，,;；\s]+", text.strip())
    kws = []
    for p in parts:
        p = p.strip().lower()
        if p and p not in kws:
            kws.append(p)
    return kws


def kw_match(text, kws):
    if text is None:
        return False
    t = str(text).lower()
    return any(k in t for k in kws)


def reg_split(path):
    """把 'HKLM\\SOFTWARE\\xx' 拆成 (根键名, 子键)。"""
    root, sub = path.split("\\", 1) if "\\" in path else (path, "")
    return root.upper(), sub


def reg_key_exists(path):
    root, sub = reg_split(path)
    if root not in REG_ROOTS:
        return False
    try:
        with winreg.OpenKey(REG_ROOTS[root], sub, 0, winreg.KEY_READ):
            return True
    except OSError:
        return False


def reg_value_exists(path, value_name):
    root, sub = reg_split(path)
    try:
        with winreg.OpenKey(REG_ROOTS[root], sub, 0, winreg.KEY_READ) as k:
            winreg.QueryValueEx(k, value_name)
            return True
    except OSError:
        return False


def enum_subkeys(root_handle, sub, limit=None):
    """枚举子键名，失败返回空列表。"""
    names = []
    try:
        with winreg.OpenKey(root_handle, sub, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
                if limit and len(names) >= limit:
                    break
    except OSError:
        pass
    return names


def read_values(root_handle, sub, max_values=50):
    """读取键下全部值，返回 [(名称, 字符串形式, 类型)]，失败返回空列表。"""
    out = []
    try:
        with winreg.OpenKey(root_handle, sub, 0, winreg.KEY_READ) as k:
            for i in range(winreg.QueryInfoKey(k)[1]):
                try:
                    name, data, vtype = winreg.EnumValue(k, i)
                except OSError:
                    break
                if isinstance(data, bytes):
                    vs = data.hex()[:80]
                else:
                    vs = str(data)[:120]
                out.append((name, vs, vtype))
                if len(out) >= max_values:
                    break
    except OSError:
        pass
    return out


def item_key(item):
    return (item["kind"], item["path"].lower(), (item.get("value") or "").lower())


def add_item(items, seen, kind, path, value, reason):
    """加入结果项：去重 + 黑名单拦截。kind: 'key' 整键删除 / 'value' 仅删值。"""
    if path.lower() in REG_DENYLIST:
        return False
    k = item_key({"kind": kind, "path": path, "value": value})
    if k in seen or len(items) >= REG_ITEM_CAP:
        return False
    seen.add(k)
    items.append({"kind": kind, "path": path, "value": value, "reason": reason})
    return True


def scan_registry(kws, deep, log):
    """
    通用注册表残留扫描。返回结果项列表：
      {kind, path, value, reason}
    """
    items, seen = [], set()

    # —— 1. 卸载信息 ——
    log("[扫描] 卸载信息 …")
    for root_name, sub in REG_UNINSTALL_KEYS:
        root = REG_ROOTS[root_name]
        for name in enum_subkeys(root, sub):
            sub_path = f"{sub}\\{name}" if sub else name
            full = f"{root_name}\\{sub_path}"
            texts = [name]
            for vn, vs, _t in read_values(root, sub_path, 30):
                if vn.lower() in ("displayname", "publisher", "installlocation",
                                  "uninstallstring", "installsource", "displayicon"):
                    texts.append(vs)
            if any(kw_match(t, kws) for t in texts):
                disp = next((vs for vn, vs, _ in read_values(root, sub_path, 30)
                             if vn.lower() == "displayname"), name)
                add_item(items, seen, "key", full, None, f"卸载信息：{disp}")

    # —— 2. 启动项 ——
    log("[扫描] 启动项 …")
    for root_name, sub in REG_RUN_KEYS:
        root = REG_ROOTS[root_name]
        for vn, vs, _t in read_values(root, sub, 500):
            if kw_match(vn, kws) or kw_match(vs, kws):
                add_item(items, seen, "value", f"{root_name}\\{sub}", vn,
                         f"启动项 → {vs[:60]}")

    # —— 3. 系统服务 ——
    log("[扫描] 系统服务 …")
    sroot_name, ssub = REG_SERVICES_KEY
    sroot = REG_ROOTS[sroot_name]
    for name in enum_subkeys(sroot, ssub):
        sub_path = f"{ssub}\\{name}"
        texts = [name]
        for vn, vs, _t in read_values(sroot, sub_path, 30):
            if vn.lower() in ("displayname", "imagepath", "description", "group"):
                texts.append(vs)
        if any(kw_match(t, kws) for t in texts):
            disp = next((vs for vn, vs, _ in read_values(sroot, sub_path, 30)
                         if vn.lower() == "displayname"), name)
            add_item(items, seen, "key", f"{sroot_name}\\{sub_path}", None,
                     f"服务：{disp}")

    # —— 4. 软件厂商键（快速：顶层键名匹配） ——
    log("[扫描] 软件残留键 …")
    for root_name, sub in REG_VENDOR_PARENTS:
        root = REG_ROOTS[root_name]
        for name in enum_subkeys(root, sub, limit=3000):
            if kw_match(name, kws):
                full = f"{root_name}\\{sub}\\{name}" if sub else f"{root_name}\\{name}"
                add_item(items, seen, "key", full, None, "软件残留键")

    # —— 5. 深度扫描（可选，遍历 SOFTWARE 全树） ——
    if deep:
        log("[扫描] 深度扫描 SOFTWARE 全树（较慢）…")
        visited = 0
        for root_name, sub in REG_DEEP_ROOTS:
            stack = [sub]
            while stack:
                if len(items) >= REG_ITEM_CAP or visited >= REG_VISIT_CAP:
                    break
                cur = stack.pop()
                visited += 1
                if visited % 50000 == 0:
                    log(f"  … 已遍历 {visited} 个键，命中 {len(items)} 项")
                root = REG_ROOTS[root_name]
                path = f"{root_name}\\{cur}"
                name = cur.rsplit("\\", 1)[-1]
                deny = path.lower() in REG_DENYLIST
                # 键名匹配 → 整键项，并剪枝（父键删除后子键无意义）
                if not deny and kw_match(name, kws):
                    add_item(items, seen, "key", path, None, "深度：键名匹配")
                    continue
                # 值匹配 → 仅删值（键保留，避免误伤容器键）
                if not deny:
                    for vn, vs, vt in read_values(root, cur, 25):
                        if vt in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                            if kw_match(vn, kws) or kw_match(vs, kws):
                                add_item(items, seen, "value", path, vn,
                                         f"深度：值匹配 → {str(vs)[:40]}")
                for child in enum_subkeys(root, cur):
                    stack.append(f"{cur}\\{child}")
        log(f"[扫描] 深度扫描完成，共遍历 {visited} 个键")

    log(f"[扫描] 完成，共发现 {len(items)} 个匹配项"
        + (f"（已达上限 {REG_ITEM_CAP}）" if len(items) >= REG_ITEM_CAP else ""))
    return items


# ---------- 注册表提权（应对删除被拒的顽固键） ----------
SE_REGISTRY_KEY = 4
OWNER_SECURITY_INFORMATION = 0x1
DACL_SECURITY_INFORMATION = 0x4
TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x8
SE_PRIVILEGE_ENABLED = 0x2


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]


def enable_privileges():
    """为当前进程开启 夺权 / 备份 / 还原 特权（删除受保护注册表键的前提）。"""
    adv = ctypes.windll.advapi32
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(kernel32.GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ctypes.byref(token)):
        return
    try:
        for name in ("SeTakeOwnershipPrivilege", "SeBackupPrivilege",
                     "SeRestorePrivilege"):
            luid = LUID()
            if adv.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                tp = TOKEN_PRIVILEGES(1, LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED))
                adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
    finally:
        kernel32.CloseHandle(token)


def take_reg_ownership(path):
    """
    夺取注册表键所有权并授予 Administrators / SYSTEM 完全控制。
    返回是否成功。仅在 reg delete 失败时调用。
    """
    try:
        root, sub = reg_split(path)
        target = REG_MACHINE_NAME[root] + ("\\" + sub if sub else "")
        enable_privileges()
        adv = ctypes.windll.advapi32

        sid = ctypes.c_void_p()
        if not adv.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(sid)):
            return False
        sd = ctypes.c_void_p()
        # SDDL：授予 BA(Administrators) 与 SY(SYSTEM) 完全控制
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                "D:(A;;GA;;;BA)(A;;GA;;;SY)", 1, ctypes.byref(sd), None):
            kernel32.LocalFree(sid)
            return False
        try:
            r1 = adv.SetNamedSecurityInfoW(target, SE_REGISTRY_KEY,
                                           OWNER_SECURITY_INFORMATION,
                                           sid, None, None, None)
            present = wintypes.BOOL()
            dacl = ctypes.c_void_p()
            defaulted = wintypes.BOOL()
            adv.GetSecurityDescriptorDacl(sd, ctypes.byref(present),
                                          ctypes.byref(dacl), ctypes.byref(defaulted))
            r2 = adv.SetNamedSecurityInfoW(target, SE_REGISTRY_KEY,
                                           DACL_SECURITY_INFORMATION,
                                           None, None, dacl, None)
            return r1 == 0 and r2 == 0
        finally:
            kernel32.LocalFree(sid)
            kernel32.LocalFree(sd)
    except Exception:
        return False


# ---------- 注册表备份与删除 ----------
def reg_backup(item, backup_dir, log):
    """删除前用 reg export 备份所属键，返回备份文件路径（失败返回 None）。"""
    os.makedirs(backup_dir, exist_ok=True)
    safe = re.sub(r'[\\/:*?"<>|]', "_", item["path"])[:120]
    if item["kind"] == "value":
        safe += "__v_" + re.sub(r'[\\/:*?"<>|]', "_", item["value"] or "(默认)")[:40]
    fname = os.path.join(backup_dir, safe + ".reg")
    r = run_hidden(["reg", "export", item["path"], fname, "/y"])
    if r is not None and r.returncode == 0 and os.path.exists(fname):
        return fname
    log(f"  [警告] 备份失败：{item['path']}")
    return None


def reg_delete_item(item, log):
    """
    删除单个注册表项（先常规删除，失败则夺权后重试）。返回是否成功。
    """
    is_value = item["kind"] == "value"
    if is_value:
        if item["value"]:
            cmd = ["reg", "delete", item["path"], "/v", item["value"], "/f"]
        else:
            cmd = ["reg", "delete", item["path"], "/ve", "/f"]
    else:
        cmd = ["reg", "delete", item["path"], "/f"]

    r = run_hidden(cmd)
    ok = r is not None and r.returncode == 0
    if not ok:
        # —— 夺权后重试 ——
        if take_reg_ownership(item["path"]):
            log("  → 已夺取注册表所有权，重试删除")
            r = run_hidden(cmd)
            ok = r is not None and r.returncode == 0

    # 结果校验（不只看返回码）
    if is_value:
        gone = not reg_value_exists(item["path"], item["value"])
    else:
        gone = not reg_key_exists(item["path"])
    return ok and gone


def app_dir():
    """软件所在目录（备份目录的父目录）。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(name):
    """定位随程序打包的资源文件（如图标），兼容源码运行与 PyInstaller 单文件。"""
    if getattr(sys, "frozen", False):
        return os.path.join(sys._MEIPASS, name)
    return os.path.join(app_dir(), name)


def make_backup_dir():
    stamp = time.strftime("%Y%m%d_%H%M%S")
    d = os.path.join(app_dir(), "backups", "reg_" + stamp)
    os.makedirs(d, exist_ok=True)
    return d


# ======================================================================
# GUI
# ======================================================================
def main():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    # —— 启动即申请管理员权限（强制删除的前提） ——
    if not is_admin():
        if relaunch_as_admin():
            return                        # 新实例已以管理员启动，本实例退出
        # 用户取消 UAC：继续以普通权限运行（能力受限，界面会提示）

    # —— 可选拖放支持 ——
    dnd_ok = False
    try:
        from tkinterdnd2 import TkinterDnD, DND_FILES
        root = TkinterDnD.Tk()
        dnd_ok = True
    except Exception:
        root = tk.Tk()

    admin = is_admin()
    root.title(f"{APP_TITLE}（{'管理员权限' if admin else '权限受限'}）")
    try:
        root.iconbitmap(resource_path("app.ico"))
    except Exception:
        pass
    root.geometry("740x700")
    root.minsize(600, 520)

    q = queue.Queue()

    nb = ttk.Notebook(root)
    nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6, 0))

    # ==================================================================
    # 页签 1：文件 / 文件夹强力删除
    # ==================================================================
    tab1 = ttk.Frame(nb)
    nb.add(tab1, text=" 文件强力删除 ")

    top = ttk.Frame(tab1, padding=(10, 8, 10, 0))
    top.pack(fill=tk.X)

    def add_paths(paths):
        existing = set(listbox.get(0, tk.END))
        for p in paths:
            p = p.strip().strip('"')
            if not p:
                continue
            if not p.startswith("\\\\?\\"):
                p = os.path.normpath(p)
            if p in existing:
                continue
            if not path_exists(p):
                append_log(f"[跳过] 路径不存在：{p}")
                continue
            existing.add(p)
            listbox.insert(tk.END, p)
        update_status()

    def add_files():
        add_paths(filedialog.askopenfilenames(title="选择要删除的文件"))

    def add_folder():
        p = filedialog.askdirectory(title="选择要删除的文件夹")
        if p:
            add_paths([p])

    def remove_selected():
        for i in reversed(listbox.curselection()):
            listbox.delete(i)
        update_status()

    def clear_all():
        listbox.delete(0, tk.END)
        update_status()

    ttk.Button(top, text="添加文件", command=add_files).pack(side=tk.LEFT, padx=(0, 6))
    ttk.Button(top, text="添加文件夹", command=add_folder).pack(side=tk.LEFT, padx=6)
    ttk.Button(top, text="移除选中", command=remove_selected).pack(side=tk.LEFT, padx=6)
    ttk.Button(top, text="清空列表", command=clear_all).pack(side=tk.LEFT, padx=6)

    mid = ttk.Frame(tab1, padding=(10, 8, 10, 0))
    mid.pack(fill=tk.BOTH, expand=True)
    hint = ttk.Label(mid, text="待删除列表（可把文件/文件夹直接拖进来，双击或按 Delete 键移除条目）",
                     foreground="#666666")
    hint.pack(anchor=tk.W)

    lb_frame = ttk.Frame(mid)
    lb_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
    listbox = tk.Listbox(lb_frame, selectmode=tk.EXTENDED, activestyle="none",
                         font=("Microsoft YaHei UI", 9))
    sb = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL, command=listbox.yview)
    listbox.configure(yscrollcommand=sb.set)
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    sb.pack(side=tk.RIGHT, fill=tk.Y)
    lb_hsb = ttk.Scrollbar(mid, orient=tk.HORIZONTAL, command=listbox.xview)
    lb_hsb.pack(fill=tk.X, pady=(2, 0))
    listbox.configure(xscrollcommand=lb_hsb.set)
    listbox.bind("<Double-Button-1>", lambda e: remove_selected())
    listbox.bind("<Delete>", lambda e: remove_selected())

    if dnd_ok:
        def on_drop(event):
            add_paths(root.tk.splitlist(event.data))
        for widget in (root, listbox, hint):
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", on_drop)

    opt = ttk.LabelFrame(tab1, text="删除选项（建议保持全选）", padding=(8, 4))
    opt.pack(fill=tk.X, padx=10, pady=(8, 0))
    var_unlock = tk.BooleanVar(value=True)
    var_grant = tk.BooleanVar(value=True)
    var_reboot = tk.BooleanVar(value=True)
    ttk.Checkbutton(opt, text="自动结束占用进程（正在运行也能删）",
                    variable=var_unlock).pack(anchor=tk.W)
    ttk.Checkbutton(opt, text="自动夺取所有权与权限（需要管理员/System 权限的文件）",
                    variable=var_grant).pack(anchor=tk.W)
    ttk.Checkbutton(opt, text="仍删不掉时，安排重启电脑后自动删除（终极兜底）",
                    variable=var_reboot).pack(anchor=tk.W)

    btn_delete = tk.Button(tab1, text="立即强力删除", bg="#c42b1c", fg="white",
                           activebackground="#a52315", activeforeground="white",
                           font=("Microsoft YaHei UI", 11, "bold"),
                           relief=tk.FLAT, cursor="hand2")
    btn_delete.pack(pady=8, ipadx=28, ipady=4)

    # ==================================================================
    # 页签 2：注册表残留清理
    # ==================================================================
    tab2 = ttk.Frame(nb)
    nb.add(tab2, text=" 注册表残留清理 ")

    reg_items = []          # 扫描结果
    reg_sel = []            # 每项勾选状态（与 reg_items 一一对应）
    reg_kws = []            # 当前扫描关键词（用于高亮）

    r_top = ttk.Frame(tab2, padding=(10, 8, 10, 0))
    r_top.pack(fill=tk.X)
    ttk.Label(r_top, text="关键词：").pack(side=tk.LEFT)
    var_kw = tk.StringVar()
    entry_kw = ttk.Entry(r_top, textvariable=var_kw, width=28)
    entry_kw.pack(side=tk.LEFT, padx=(4, 8))
    var_deep = tk.BooleanVar(value=False)
    ttk.Checkbutton(r_top, text="深度扫描（慢）", variable=var_deep).pack(side=tk.LEFT)
    btn_scan = ttk.Button(r_top, text="开始扫描")
    btn_scan.pack(side=tk.LEFT, padx=8)

    ttk.Label(tab2, foreground="#666666", padding=(10, 4, 10, 0),
              text="示例：360 qihoo ｜ 2345 ｜ kingsoft；按住左键拖出蓝色范围统一勾选/取消，"
                   "单击切换单行，关键词黄色高亮").pack(anchor=tk.W)

    # —— 结果区：Text 实现（支持横向滚动 + 关键词高亮 + 点击勾选） ——
    r_mid = ttk.Frame(tab2, padding=(10, 4, 10, 0))
    r_mid.pack(fill=tk.BOTH, expand=True)
    reg_text = tk.Text(r_mid, wrap=tk.NONE, height=10, cursor="arrow",
                       font=("Consolas", 9), state=tk.DISABLED)
    r_sb = ttk.Scrollbar(r_mid, orient=tk.VERTICAL, command=reg_text.yview)
    r_sb.pack(side=tk.RIGHT, fill=tk.Y)
    reg_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    r_hsb = ttk.Scrollbar(tab2, orient=tk.HORIZONTAL, command=reg_text.xview)
    r_hsb.pack(fill=tk.X, padx=10)
    reg_text.configure(yscrollcommand=r_sb.set, xscrollcommand=r_hsb.set)
    reg_text.tag_configure("kw", background="#ffe58f", foreground="#c42b1c")
    reg_text.tag_configure("marq", background="#bcdcff")   # 拖选范围带（Windows 蓝）

    r_btn = ttk.Frame(tab2, padding=(10, 6))
    r_btn.pack(fill=tk.X)

    def reg_display(item):
        tag = {"key": "整键", "value": "值"}[item["kind"]]
        v = f" → 值:{item['value'] or '(默认)'}" if item["kind"] == "value" else ""
        return f"[{tag}] {item['path']}{v} ｜ {item['reason']}"

    def refresh_reg_list():
        """重绘结果列表：勾选符 + 关键词高亮。"""
        reg_text.configure(state=tk.NORMAL)
        reg_text.delete("1.0", tk.END)
        for i, it in enumerate(reg_items):
            mark = "☑" if reg_sel[i] else "☐"
            reg_text.insert(tk.END, f"{mark} {reg_display(it)}\n")
        kws = [k for k in reg_kws if k]
        if kws:
            for ln in range(1, len(reg_items) + 1):
                line_txt = reg_text.get(f"{ln}.0", f"{ln}.end").lower()
                for k in kws:
                    start = 0
                    while True:
                        idx = line_txt.find(k, start)
                        if idx < 0:
                            break
                        reg_text.tag_add("kw", f"{ln}.{idx}", f"{ln}.{idx + len(k)}")
                        start = idx + len(k)
        reg_text.configure(state=tk.DISABLED)
        update_status()

    def reg_select_all():
        for i in range(len(reg_sel)):
            reg_sel[i] = True
        refresh_reg_list()

    def reg_select_none():
        for i in range(len(reg_sel)):
            reg_sel[i] = False
        refresh_reg_list()

    # 拖动选择：按住左键拖出蓝色范围带，松开后统一勾选/取消该范围；单击切换单行
    _drag = {"anchor": -1, "state": True, "active": False, "last": -1}

    def _reg_line_at(event):
        try:
            return int(reg_text.index(f"@{event.x},{event.y}").split(".")[0]) - 1
        except Exception:
            return -1

    def _set_line_mark(ln, state):
        reg_sel[ln] = state
        reg_text.configure(state=tk.NORMAL)
        reg_text.delete(f"{ln + 1}.0", f"{ln + 1}.1")
        reg_text.insert(f"{ln + 1}.0", "☑" if state else "☐")
        reg_text.configure(state=tk.DISABLED)

    def _draw_marq(lo, hi):
        """用蓝色高亮带标出当前拖动范围（类似 Windows 拖选矩形）。"""
        reg_text.tag_remove("marq", "1.0", tk.END)
        if 0 <= lo <= hi < len(reg_items):
            reg_text.tag_add("marq", f"{lo + 1}.0", f"{hi + 1}.end + 1c")
            reg_text.tag_raise("kw")          # 关键词高亮保持在蓝带之上可见

    def on_reg_press(event):
        ln = _reg_line_at(event)
        if 0 <= ln < len(reg_items):
            _drag["anchor"] = ln
            _drag["state"] = not reg_sel[ln]   # 本次拖动要统一设置的目标状态
            _drag["active"] = False
            _drag["last"] = ln
        return "break"

    def on_reg_drag(event):
        if _drag["anchor"] < 0:
            return "break"
        ln = _reg_line_at(event)
        if ln < 0:
            return "break"
        _drag["active"] = True
        _drag["last"] = ln
        lo, hi = sorted((_drag["anchor"], min(ln, len(reg_items) - 1)))
        _draw_marq(lo, hi)
        return "break"

    def on_reg_release(event):
        reg_text.tag_remove("marq", "1.0", tk.END)
        if _drag["anchor"] >= 0:
            if _drag["active"]:
                ln = _reg_line_at(event)
                if ln < 0:
                    ln = _drag["last"]
                lo, hi = sorted((_drag["anchor"], min(ln, len(reg_items) - 1)))
                for i in range(lo, hi + 1):
                    if reg_sel[i] != _drag["state"]:
                        _set_line_mark(i, _drag["state"])
            else:
                # 单击：只切换当前行
                _set_line_mark(_drag["anchor"], _drag["state"])
        _drag["anchor"] = -1
        _drag["active"] = False
        return "break"

    reg_text.bind("<Button-1>", on_reg_press)
    reg_text.bind("<B1-Motion>", on_reg_drag)
    reg_text.bind("<ButtonRelease-1>", on_reg_release)

    # ---------- 备份管理 ----------
    def fmt_size(n):
        """字节数转可读字符串。"""
        n = float(n)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024

    def open_backup_manager():
        """备份管理窗口：查看大小 / 删除历史 .reg 备份。"""
        win = tk.Toplevel(root)
        win.title("备份管理")
        win.geometry("620x380")
        win.transient(root)
        try:
            win.iconbitmap(resource_path("app.ico"))
        except Exception:
            pass

        ttk.Label(win, padding=(10, 8, 10, 0), foreground="#666666",
                  text="删除注册表项前导出的 .reg 备份（双击 .reg 文件可还原注册表）"
                  ).pack(anchor=tk.W)
        mid = ttk.Frame(win, padding=(10, 6))
        mid.pack(fill=tk.BOTH, expand=True)
        lb = tk.Listbox(mid, selectmode=tk.EXTENDED, activestyle="none",
                        font=("Microsoft YaHei UI", 9))
        sbk = ttk.Scrollbar(mid, orient=tk.VERTICAL, command=lb.yview)
        lb.configure(yscrollcommand=sbk.set)
        lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sbk.pack(side=tk.RIGHT, fill=tk.Y)

        backup_entries = []   # [(名称, 绝对路径, 大小)]

        def dir_size(p):
            total = 0
            for r, _ds, fs in os.walk(p):
                for f in fs:
                    try:
                        total += os.path.getsize(os.path.join(r, f))
                    except OSError:
                        pass
            return total

        def refresh_backups():
            backup_entries.clear()
            lb.delete(0, tk.END)
            rootd = os.path.join(app_dir(), "backups")
            os.makedirs(rootd, exist_ok=True)
            total = 0
            for name in sorted(os.listdir(rootd), reverse=True):
                p = os.path.join(rootd, name)
                try:
                    size = dir_size(p) if os.path.isdir(p) else os.path.getsize(p)
                except OSError:
                    continue
                backup_entries.append((name, p, size))
                total += size
                lb.insert(tk.END, f"{name} ｜ {fmt_size(size)}")
            lbl_total.configure(text=f"共 {len(backup_entries)} 个备份，占用 {fmt_size(total)}")

        def delete_entry(name, p):
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)

        def delete_selected():
            idxs = list(lb.curselection())
            if not idxs:
                return
            if not messagebox.askyesno("确认", f"删除选中的 {len(idxs)} 个备份？"
                                               f"删除后无法用其还原注册表。",
                                       icon="warning", parent=win):
                return
            for i in reversed(idxs):
                name, p, _ = backup_entries[i]
                try:
                    delete_entry(name, p)
                    append_log(f"[备份] 已删除备份：{name}")
                except OSError as e:
                    append_log(f"[备份] 删除失败 {name}：{e}")
            refresh_backups()

        def delete_all():
            if not backup_entries:
                return
            if not messagebox.askyesno("确认", f"删除全部 {len(backup_entries)} 个备份？",
                                       icon="warning", parent=win):
                return
            for name, p, _ in backup_entries:
                try:
                    delete_entry(name, p)
                except OSError:
                    pass
            append_log("[备份] 已清空全部备份")
            refresh_backups()

        bar = ttk.Frame(win, padding=(10, 4, 10, 10))
        bar.pack(fill=tk.X)
        ttk.Button(bar, text="删除选中", command=delete_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(bar, text="全部删除", command=delete_all).pack(side=tk.LEFT, padx=6)
        ttk.Button(bar, text="打开目录",
                   command=lambda: os.startfile(os.path.join(app_dir(), "backups"))
                   ).pack(side=tk.LEFT, padx=6)
        lbl_total = ttk.Label(bar, text="", foreground="#666666")
        lbl_total.pack(side=tk.RIGHT)
        refresh_backups()

    var_backup = tk.BooleanVar(value=True)
    ttk.Checkbutton(r_btn, text="删除前自动备份 .reg（推荐）",
                    variable=var_backup).pack(side=tk.LEFT, padx=(0, 10))
    ttk.Button(r_btn, text="全选", command=reg_select_all).pack(side=tk.LEFT, padx=(0, 6))
    ttk.Button(r_btn, text="全不选", command=reg_select_none).pack(side=tk.LEFT, padx=6)
    btn_reg_del = tk.Button(r_btn, text="删除选中项", bg="#c42b1c", fg="white",
                            activebackground="#a52315", activeforeground="white",
                            font=("Microsoft YaHei UI", 10, "bold"),
                            relief=tk.FLAT, cursor="hand2")
    btn_reg_del.pack(side=tk.LEFT, padx=12)
    ttk.Button(r_btn, text="备份管理", command=open_backup_manager).pack(side=tk.LEFT, padx=6)

    # ---------- 扫描 ----------
    def scan_worker(kws, deep):
        try:
            result = scan_registry(kws, deep, lambda m: q.put(("log", m)))
            q.put(("reg_scan_done", result))
        except Exception as e:
            q.put(("log", f"[异常] 扫描出错：{e}"))
            q.put(("reg_scan_done", []))

    def on_scan():
        nonlocal reg_kws
        kws = parse_keywords(var_kw.get())
        if not kws:
            messagebox.showinfo("提示", "请输入关键词（如：360 qihoo）。")
            return
        if any(len(k) < 2 for k in kws):
            messagebox.showinfo("提示", "单个关键词至少 2 个字符，避免误匹配。")
            return
        btn_scan.config(state=tk.DISABLED, text="扫描中…")
        reg_kws = kws
        append_log("=" * 60)
        append_log(f"注册表扫描关键词：{'、'.join(kws)}"
                   f"（{'深度' if var_deep.get() else '快速'}模式）")
        threading.Thread(target=scan_worker,
                         args=(kws, var_deep.get()), daemon=True).start()

    def on_reg_scan_done(result):
        nonlocal reg_items, reg_sel
        reg_items = result
        reg_sel = [True] * len(result)   # 默认全选
        refresh_reg_list()
        btn_scan.config(state=tk.NORMAL, text="开始扫描")
        if result:
            reg_select_all()
            messagebox.showinfo("扫描完成",
                                f"发现 {len(result)} 个匹配项，已全部选中。\n"
                                f"请逐项核对后再删除（删除前会自动备份）。")
        else:
            messagebox.showinfo("扫描完成", "未发现匹配的注册表残留。")

    btn_scan.config(command=on_scan)
    entry_kw.bind("<Return>", lambda e: on_scan())

    # ---------- 删除 ----------
    def reg_del_worker(selected, backup_dir, do_backup):
        ok, fail, deleted, had_service = 0, 0, [], False
        for it in selected:
            q.put(("log", f"[删除] {reg_display(it)}"))
            if do_backup:
                reg_backup(it, backup_dir, lambda m: q.put(("log", m)))
            else:
                q.put(("log", "  [提示] 已按设置跳过备份"))
            try:
                success = reg_delete_item(it, lambda m: q.put(("log", m)))
            except Exception as e:
                success = False
                q.put(("log", f"  [异常] {e}"))
            if success:
                ok += 1
                deleted.append(it)
                if it["kind"] == "key" and "\\services\\" in it["path"].lower():
                    had_service = True
                q.put(("log", "  [成功]"))
            else:
                fail += 1
                q.put(("log", "  [失败] 可能被驱动保护（如软件仍在运行，请先卸载/关闭自我保护）"))
        q.put(("reg_del_done", (ok, fail, deleted, backup_dir, had_service)))

    def on_reg_delete():
        selected = [it for i, it in enumerate(reg_items) if reg_sel[i]]
        if not selected:
            messagebox.showinfo("提示", "请先扫描并勾选要删除的注册表项。")
            return
        n_key = sum(1 for it in selected if it["kind"] == "key")
        n_val = len(selected) - n_key
        do_backup = var_backup.get()
        tip = ("删除前会自动导出 .reg 备份到 backups 目录（双击可还原）。" if do_backup
               else "【注意】已关闭自动备份，删除后不可还原！")
        if not messagebox.askyesno(
                "最后确认",
                f"即将删除 {len(selected)} 个注册表项（整键 {n_key} 个，值 {n_val} 个）。\n\n"
                f"{tip}\n\n确定继续吗？", icon="warning"):
            return
        backup_dir = make_backup_dir() if do_backup else None
        append_log("=" * 60)
        append_log(f"开始删除 {len(selected)} 个注册表项"
                   + (f"，备份目录：{backup_dir}" if do_backup else "（未备份）"))
        btn_reg_del.config(state=tk.DISABLED)
        threading.Thread(target=reg_del_worker,
                         args=(selected, backup_dir, do_backup), daemon=True).start()

    def on_reg_del_done(payload):
        nonlocal reg_items, reg_sel
        ok, fail, deleted, backup_dir, had_service = payload
        deleted_keys = {item_key(it) for it in deleted}
        keep = [i for i, it in enumerate(reg_items) if item_key(it) not in deleted_keys]
        reg_items = [reg_items[i] for i in keep]
        reg_sel = [reg_sel[i] for i in keep]
        refresh_reg_list()
        btn_reg_del.config(state=tk.NORMAL)
        append_log(f"注册表删除完成：成功 {ok} 个，失败 {fail} 个")
        append_log("=" * 60)
        msg = f"成功删除 {ok} 个，失败 {fail} 个。"
        if backup_dir:
            msg += f"\n\n备份位置：{backup_dir}"
        if had_service:
            msg += "\n\n含系统服务键，建议【重启电脑】使服务彻底失效。"
        messagebox.showinfo("完成" if fail == 0 else "完成（有失败）", msg)

    btn_reg_del.config(command=on_reg_delete)

    # ==================================================================
    # 共享日志区
    # ==================================================================
    log_frame = ttk.LabelFrame(root, text="执行日志", padding=(6, 4))
    log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(2, 6))
    log_text = tk.Text(log_frame, height=8, state=tk.DISABLED, wrap=tk.NONE,
                       font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4")
    log_sb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=log_text.yview)
    log_text.configure(yscrollcommand=log_sb.set)
    log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    log_sb.pack(side=tk.RIGHT, fill=tk.Y)

    status = ttk.Label(root, text="", anchor=tk.W, padding=(10, 2))
    status.pack(fill=tk.X)

    def append_log(msg):
        log_text.configure(state=tk.NORMAL)
        log_text.insert(tk.END, msg + "\n")
        log_text.see(tk.END)
        log_text.configure(state=tk.DISABLED)

    def update_status():
        n = listbox.size()
        status.configure(
            text=f"文件待删 {n} 项 ｜ 注册表结果 {len(reg_items)} 项 ｜ 当前权限："
                 f"{'管理员（完整能力）' if admin else '普通（建议以管理员身份重启本程序）'}")

    # ---------- 文件删除执行（后台线程，防止界面卡死） ----------
    def worker(items, options):
        ok, fail, reboot_cnt = 0, 0, 0
        deleted_items = []
        for p in items:
            try:
                success, need_reboot = force_delete_path(p, lambda m: q.put(("log", m)), options)
            except Exception as e:
                success, need_reboot = False, False
                q.put(("log", f"[异常] {p}：{e}"))
            if success:
                ok += 1
                if not need_reboot:
                    deleted_items.append(p)
            else:
                fail += 1
            if need_reboot:
                reboot_cnt += 1
        q.put(("done", (ok, fail, reboot_cnt, deleted_items)))

    def on_delete():
        items = list(listbox.get(0, tk.END))
        if not items:
            messagebox.showinfo("提示", "请先添加要删除的文件或文件夹。")
            return
        if not messagebox.askyesno(
                "最后确认",
                f"即将【永久删除】 {len(items)} 个项目，不可恢复！\n\n"
                f"正在运行的程序会被强制结束，系统权限文件也会被强删。\n\n确定继续吗？",
                icon="warning"):
            return
        options = {"unlock": var_unlock.get(),
                   "grant": var_grant.get(),
                   "reboot": var_reboot.get()}
        btn_delete.config(state=tk.DISABLED, text="删 除 中 …")
        append_log("=" * 60)
        append_log(f"开始强制删除 {len(items)} 个项目 …")
        threading.Thread(target=worker, args=(items, options), daemon=True).start()

    def on_done(payload):
        ok, fail, reboot_cnt, deleted_items = payload
        for p in deleted_items:
            try:
                idx = listbox.get(0, tk.END).index(p)
                listbox.delete(idx)
            except ValueError:
                pass
        update_status()
        btn_delete.config(state=tk.NORMAL, text="立 即 强 力 删 除")
        append_log(f"完成：成功 {ok} 个，失败 {fail} 个"
                   + (f"，其中 {reboot_cnt} 个将在重启后删除" if reboot_cnt else ""))
        append_log("=" * 60)

        if fail == 0 and reboot_cnt == 0:
            messagebox.showinfo("完成", f"全部 {ok} 个项目已成功删除。")
        elif reboot_cnt > 0:
            if messagebox.askyesno(
                    "需要重启",
                    f"成功处理 {ok} 个，失败 {fail} 个。\n\n"
                    f"其中 {reboot_cnt} 个项目占用过深，已安排在【重启电脑后】自动删除。\n\n"
                    f"是否立即重启电脑完成删除？"):
                run_hidden(["shutdown", "/r", "/t", "5"])
                messagebox.showinfo("提示", "电脑将在 5 秒后重启。\n如需取消，请立即运行：shutdown /a")
        else:
            messagebox.showwarning("完成（有失败）",
                                   f"成功 {ok} 个，失败 {fail} 个。\n请查看日志了解失败原因。")

    def poll_queue():
        try:
            while True:
                kind, payload = q.get_nowait()
                if kind == "log":
                    append_log(payload)
                elif kind == "done":
                    on_done(payload)
                elif kind == "reg_scan_done":
                    on_reg_scan_done(payload)
                elif kind == "reg_del_done":
                    on_reg_del_done(payload)
        except queue.Empty:
            pass
        root.after(100, poll_queue)

    btn_delete.config(command=on_delete)

    # 支持把文件拖到 exe 图标上启动（命令行参数）
    cli_paths = [a for a in sys.argv[1:] if not a.startswith("-")]
    if cli_paths:
        root.after(100, lambda: add_paths(cli_paths))

    update_status()
    root.after(100, poll_queue)
    root.mainloop()


if __name__ == "__main__":
    main()
