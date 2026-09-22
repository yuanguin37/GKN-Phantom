# APK 逆向与脱壳手册（APK Reversing & Unpacking）

> 适用版本：v5.10.0 起
> 流水线：**快筛 → 壳识别 → 脱壳 → 全量还原 → 产物交付**
>
> ⚠️ **合规红线**：仅对**自有 App**、**已获书面授权**的目标或**公开靶场样本**
> 做逆向与脱壳。不得对第三方应用商店 App 做未授权逆向，
> 不得传播、转售反编译产物，不得用于攻击非授权目标。

---

## 0. 为什么要分三段

一个 100MB 的加固包，全量反编译可能要十几分钟，而其中 90% 的时间
花在你根本不关心的第三方 SDK 上。

**分段的收益**：

| 段 | 目标 | 耗时 | 产出 |
|---|---|---|---|
| 快筛 | 不反编译，直接从 APK 拿结论 | 秒级 | 组件矩阵、密钥、端点、加固判定 |
| 脱壳 | 还原被壳保护的 dex | 分钟级 | 原始 dex + so + assets |
| 全量还原 | 得到可读源码与资源 | 分钟~十分钟 | JADX 工程 / apktool 产物 |

**原则：先用快筛决定"值不值得脱壳、脱完先看哪个 dex"**，
不要上来就全量反编译。

---

## 1. 快筛（秒级）

```bash
python3 scripts/apk_recon.py target.apk --secrets --json recon.json
```

一次拿到：

1. **包元信息** — 包名、min/target SDK、`debuggable` / `allowBackup` / `usesCleartextTraffic`。
2. **组件矩阵** — 已标出「exported=true 且无 permission」的高风险组件。
3. **权限清单** — 含自定义 permission（注意 protectionLevel 是否 normal）。
4. **加固粗判** — `lib/` 下特征 so、`assets/` 内异常 dex/so、dex 数量异常。
5. **密钥与端点速筛** — 已脱敏的密钥命中 + 内网地址/高价值路径。

> 快筛命中密钥时**先验证密钥是否可用**（`httpRequest` 调后端）——
> 这通常是最快出成果的一步，且不需要脱壳。

---

## 2. 壳识别

### 2.1 三类信号

**信号 A：`lib/` 下的特征 so**（`apk_recon.py` 已内置匹配）

| 特征前缀 | 厂商 |
|---|---|
| `libjiagu*` / `libjgdtc*` | 360 加固 |
| `libshell*` / `libDexHelper*` | 腾讯乐固 |
| `libmobisec*` | 阿里聚安全 |
| `libnesec*` | 网易易盾 |
| `libnqshield*` / `libnsafer*` | 梆梆安全 |
| `libbaiduprotect*` | 百度加固 |
| `libexec*` / `libsgmain*` | 阿里系（含安全 SDK） |
| `libkwscmm*` / `libkgis*` | 几维/网秦系 |

**信号 B：dex 异常**

- `classes.dex` 极小（几十 KB）且以 `lib/` 下的 so 为主 → 典型整体加固。
- dex 头部字符串异常：`strings classes.dex | head` 看不到正常类名。
- 多 dex 但只有第一个有真实业务包名。

**信号 C：Application 类异常**

- `AndroidManifest.xml` 的 `android:name` 指向加固壳类
  （如 `com.stub.StubApp`、`com.tencent.StubShell.TxAppEntry`、
  `com.wrapper.proxyapplication.WrapperProxyApplication`）。
  快筛不解析 `application.name`，可在全量还原后确认。

### 2.2 判定结论

- **无壳** → 直接跳第 4 节全量还原。
- **有壳** → 走第 3 节脱壳；同时**先跑完快筛的密钥/端点部分**（加固不保护字符串池之外的资源）。

---

## 3. 脱壳

### 3.1 选择策略

| 场景 | 推荐 | 说明 |
|---|---|---|
| 有 Root 测试机 | Frida 系脱壳（`frida-dexdump`、`BlackDex`、`Youpk`） | 最快，一次性拿到多 dex |
| 无 Root | 重打包 + 静态脱壳工具；或真机 + 支持非 root 的脱壳 App | 见 3.3 |
| 只关心字符串/接口 | **不脱壳**，直接在壳 so 与 assets 里找 | 很多接口清单与密钥不加密 |
| 只想看组件 | **不脱壳**，`AndroidManifest.xml` 几乎从不加密 | 快筛已覆盖 |

### 3.2 标准流程（有 Root）

```bash
# 1) 推送并启动 frida-server（版本需与 frida 客户端一致）
adb push frida-server /data/local/tmp/ && adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"

# 2) 确认可见进程
frida-ps -U | grep <包名>

# 3) spawn 模式启动并 dump dex（先启动，让壳完成解密）
frida-dexdump -U -f <包名>
# 或使用 objection / 专用脚本；dump 产物通常是多个 .dex

# 4) 校验：dump 出的 dex 应能反编译出真实包名的类
```

**关键点**：**spawn 模式**（先挂载再启动）比 attach 更可靠，
因为多数壳在 Application 初始化阶段解密，attach 可能已错过时机。
若 dump 到的 dex 不完整，尝试在壳的 `attachBaseContext` / `onCreate` 之后、
业务代码执行时再 dump。

### 3.3 无 Root 降级路径

| 手段 | 原理 | 限制 |
|---|---|---|
| 静态脱壳工具 | 模拟执行壳的解密例程，静态还原 dex | 对新版壳（VMP）常失效 |
| 重打包 + 替换壳的 Application | 用官方签名工具重签后安装 | 可能触发签名校验/反调试 |
| 改用真机 + 支持非 root 的方案 | 部分工具利用系统漏洞或无障碍 | 兼容性差 |
| **绕开脱壳** | 直接静态分析壳 so / assets / 资源 | 拿不到 Java 层逻辑 |

**报告要求**：如果因无 Root 无法脱壳，必须在报告"限制与缓解"写明
未还原的范围与所需条件，不得声称"已完整审计"。

---

## 4. 全量还原

### 4.1 工具选择

| 目标 | 工具 | 说明 |
|---|---|---|
| Java 源码（首选） | `jadx` / `jadx-gui` | 直接出可读 Java，交叉引用方便 |
| 资源与 smali | `apktool d -f target.apk -o out/` | 保留 `AndroidManifest.xml` 明文与 `res/` |
| 只转 dex | `dex2jar` + `jd-gui` | 老旧但轻量 |
| so 分析 | `ghidra` / `ida` | 看壳与 native 逻辑 |

### 4.2 还原后的产物结构

```
out/
├── AndroidManifest.xml          # 明文，组件面权威来源（与快筛交叉验证）
├── smali/ 或 sources/           # 代码
├── res/                         # 资源（字符串常被用来藏端点）
├── assets/                      # 常含 H5、配置、加密数据、二次 dex
└── lib/<abi>/*.so               # native 库
```

**必看清单**：

1. `res/values/strings.xml`（`apktool` 产物）— 端点与密钥常在此。
2. `assets/` — H5 页面、`config.json`、`.so`/`.dex`（加固残留）、证书。
3. `AndroidManifest.xml` — 与 `apk_recon.py` 的组件矩阵**交叉校验**，
   差异说明壳做过二次处理。
4. 入口 `Application` 类 — 看是否被壳替换，以及业务初始化逻辑。

### 4.3 H5 / 小程序式逻辑

很多 App 用 WebView 承载核心业务 → `assets/` 里的 H5 与 JS
往往比 Java 层更容易出漏洞（接口清单、鉴权逻辑、加密算法全在里面）。
配合 `js_analyzer.py` 处理。

---

## 5. 产物交付

1. **不入库**：`unpacked/`、`sources/` 等产物**不提交到仓库**，
   写进 `.gitignore`（本项目已忽略 `hunts/`、`reports/`）。
2. **线索板**：只记**脱敏结论**（走了多少 dex、找到哪些端点、哪些密钥可用），
   原始产物路径放 `hunts/<目标>/raw/`（该目录不共享）。
3. **报告**：组件/密钥类 finding 的证据用**可复制命令 + 实际效果**，
   不要把整段反编译源码贴进报告（既冗长又可能泄露第三方代码）。

---

## 6. 验收标准

1. 快筛输出已归档（`recon.json`），组件矩阵已写入线索板。
2. 壳识别结论明确（有壳/无壳 + 依据），**不得以"疑似"含糊带过**。
3. 无壳或成功脱壳 → 全量还原产物可用于审计；
   无法脱壳 → 明确写出未覆盖范围与所需条件。
4. 反编译产物**不入库、不公开**；线索板只存脱敏结论。
5. 至少一个 finding 走通：检测 → `judge` → `report_docx --gate-only` → DOCX。

---

结束。组件验证见 `references/android_audit.md`；越权口径见 `references/business_logic_playbook.md`。
