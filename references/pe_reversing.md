# Windows PE 逆向手册（PE Reversing）

> 适用版本：v5.11.0 起
> 三段结构：**静态分析 → 动态分析 → 漏洞定位**
> 覆盖：PE 结构 · 编译器与保护机制指纹 · 加壳识别 · 字符串与资源提取 ·
> `.NET` 元数据还原 · 行为监控 · 反调试/反虚拟化识别 · 协议逆向 ·
> 内存破坏类漏洞（栈/堆溢出、格式化字符串、UAF、整数溢出）· DLL 劫持。
>
> ⚠️ **合规红线**：仅分析**自有软件**、**已获书面授权**的样本，
> 或**公开靶场**（如 exploit-db / 各类 CTF 与恶意样本分析训练平台提供的环境）。
> 不得分析来源不明的恶意样本于生产主机；不得对第三方软件做未授权逆向。
> **所有动态分析必须在隔离虚拟机/沙箱中进行，禁止联网的真实主机。**

---

## 0. 定位

这是本技能最后落地的知识域，也是"Phantom"（幽灵 / 二进制）这个名字的本义。

它与前三个域的差别在于：**没有 HTTP 流量可以观察**，
所有证据来自**二进制本身的静态结构与进程的运行时行为**。

因此本域的验收标准与前三个域不同：

> **静态可疑点 = lead；可复现的崩溃 / 任意代码执行 = finding。**

---

## 1. 静态分析

### 1.1 PE 结构必查项

| 结构 | 位置 | 关注点 |
|---|---|---|
| DOS Header | `MZ` + `e_lfanew`(0x3C) | 是否被篡改指向异常偏移 |
| COFF Header | `PE\0\0` 之后 | 节数量、时间戳（编译时间可作指纹） |
| Optional Header | `Magic` | `0x10B`=PE32，`0x20B`=PE32+ |
| 保护机制标志 | `DllCharacteristics` | `DYNAMICBASE`(ASLR) / `NXCOMPAT`(DEP) / `GUARD_CF`(CFG) / `HIGH_ENTROPY_VA` |
| 节表 | 节名 / `VirtualSize` / `RawSize` / `Characteristics` | 节名异常、`RawSize` 远小于 `VirtualSize`（加壳典型） |
| Import 表 | `DataDirectory[1]` | 导入项极少（只有 `LoadLibrary`+`GetProcAddress`）→ 加壳/动态解析 |
| Export 表 | `DataDirectory[0]` | DLL 导出的敏感函数（`LoadLibrary` 包装、RPC 入口） |
| TLS 回调 | `DataDirectory[9]` | **TLS 回调在主函数前执行**，常被用于反调试与解密 |
| 资源节 | `.rsrc` | 内嵌的加密载荷、二次 PE、配置 |
| 重定位表 | `.reloc` | 缺失则 ASLR 无法生效 |

**快速核对**（`pestudio` / `PE-bear` / `CFF Explorer` 一次给全）。
**命令行核对**：

```powershell
# 保护机制与节信息（用 .NET 反射粗读 Optional Header 亦可）
Get-Item .\sample.exe | Select-Object -ExpandProperty VersionInfo
# 或用 dumpbin（VS 自带）
dumpbin /headers .\sample.exe
dumpbin /imports .\sample.exe
```

### 1.2 编译器与语言指纹

| 特征 | 判断 |
|---|---|
| `.text` + `msvcp*.dll` / `vcruntime*.dll` | MSVC C++ |
| `mscoree.dll` 导入 + `BSJB` 签名 | **.NET / C#**（改用 dnSpy / ILSpy） |
| `mingw` / `libgcc` / `.eh_frame` | MinGW / GCC |
| `.themida` / `.vmp0` | 商业壳（见 1.3） |
| `UPX0` / `UPX1` | UPX（可直接 `upx -d` 脱） |
| 大量 `Rust` panic 字符串 | Rust |

> **.NET 优先走元数据还原**：`dnSpy` / `ILSpy` 可直接看到接近源码的 IL，
> 效率远高于 native 逆向。加密的商业 .NET 壳（.NET Reactor / ConfuserEx）
> 才需要动态脱壳（dnSpy + 反混淆工具）。

### 1.3 加壳识别

**四类信号**：

1. **节名**：`UPX0/UPX1`、`.vmp0/.vmp1`（VMProtect）、`.themida`、`.enigma`、`.aspack`。
2. **入口点位置**：EP 落在最后一个节、或 EP 在节表声明的第一个节之外。
3. **节熵**：> 7.0 说明节内数据是压缩/加密的（`DIE`/`Detect It Easy` 直接给熵值）。
4. **导入表**：只有 `LoadLibraryA` + `GetProcAddress` 两个导入 → 运行时动态解析。

**结论口径**：

- UPX → `upx -d` 直接脱，几乎无损。
- 商业壳（VMProtect / Themida / Enigma）→ **不强求脱壳**，
  改用"动态行为分析 + 内存 dump + 关键 API Hook"路线，并在报告中
  明确写出"因壳保护，静态覆盖受限"。

### 1.4 字符串与资源

```powershell
# 字符串（ASCII/Unicode），筛出 URL、路径、注册表、命令
strings.exe -n 6 .\sample.exe > strings.txt      # Sysinternals
# 或：python -c "..." 自写提取
```

重点：URL / IP / 域名 / 文件路径 / 注册表键 / 命令行模板 /
计划任务名 / 服务名 / 互斥体名 / 硬编码密钥 / 调试路径（泄漏源码结构）。

资源节用 `Resource Hacker` 打开，找内嵌 PE / 加密 blob / 配置。

---

## 2. 动态分析

> **前置**：隔离虚拟机（快照可回滚）、无真实网络或仅内网靶机、
> 关闭共享文件夹与剪贴板共享。

### 2.1 行为监控

| 观察面 | 工具 | 关注点 |
|---|---|---|
| 文件系统 | Process Monitor (Procmon) | 创建/写入/删除路径，**`NAME NOT FOUND` 是 DLL 劫持线索** |
| 注册表 | Procmon | `Run` 键、服务键、COM 注册、安全软件键 |
| 网络 | Procmon / Wireshark / Fiddler | 外连地址、协议、明文凭据 |
| 进程 | Process Hacker | 子进程、注入（远程线程）、句柄 |
| API | API Monitor | 关键 API 调用序列与参数 |

### 2.2 反调试 / 反虚拟化识别

常见手段与识别点：

| 手段 | 识别特征 |
|---|---|
| `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` | API 调用 + 分支 |
| `NtQueryInformationProcess`（`ProcessDebugPort/Flags`） | 直接系统调用 |
| `PEB.BeingDebugged` 直读 | 无 API 调用的 `fs:[0x30]` 访问 |
| 时间差检测（`rdtsc` / `QueryPerformanceCounter`） | 反单步 |
| 异常处理自检（`SetUnhandledExceptionFilter`） | 触发 `int3`/`0xCC` 自检 |
| 虚拟化指纹（CPUID hypervisor bit、注册表 `Disk\Enum`、进程名 vmware/vbox） | 检测沙箱 |
| 硬件断点检测（`GetThreadContext` + Dr0-Dr7） | 反硬件断点 |

**处理原则**：先**定位**检测点（静态找 API/常量），再针对性 **patch 或 Hook**，
不要盲目用"反反调试插件"。记录每条绕过对应的**偏移与 patch 内容**（可复现要求）。

---

## 3. 漏洞定位

### 3.1 优先看保护机制缺失

用 `pestudio` / `dumpbin /headers` 检查：

| 缺失项 | 影响 |
|---|---|
| 无 `NXCOMPAT`（DEP） | 栈/堆可执行 → 溢出直接跳 shellcode |
| 无 `DYNAMICBASE`（ASLR） | 地址固定 → ROP 无需泄漏 |
| 无 `/GS`（栈 cookie） | 栈溢出无 canary |
| 无 `GUARD_CF`（CFG） | 间接调用目标不受限 |
| 无 `SAFESEH` | 异常处理链可被覆盖 |

**这一项本身就是高危信号**，且极大降低利用难度。

### 3.2 内存破坏类

| 类 | 静态信号 | 动态验证 |
|---|---|---|
| 栈溢出 | `strcpy`/`sprintf`/`gets`/`scanf("%s")`/`memcpy` 到栈缓冲且长度来自外部 | 超长输入 → 崩溃且**可观察到 EIP/RIP 可控** |
| 堆溢出 | 堆分配 + 越界写、长度由输入计算 | 相邻堆块被覆盖、崩溃模式 |
| 格式化字符串 | `printf`/`syslog` 家族第一个参数为用户可控 | 输入 `%x%x%x` 观察到栈数据泄漏 |
| 整数溢出 | 长度计算 `a*b` / `a+b` 后用于分配或拷贝 | 绕过长度校验（如 `0xFFFFFFFF + 1 = 0`） |
| UAF | `free` 后仍被使用/回调 | 崩溃地址指向已释放内存、可控重分配 |
| 类型混淆 | 联合体/虚表指针可控 | 调用可控地址 |

**定位流程（mona.py）**：

```
!mona pc / !mona pattern_offset <eip>   # 找偏移
!mona modules                            # 找无保护的模块（无 ASLR/DEP）
!mona find -s "\xff\xe4" -m <module>     # jmp esp
!mona rop -m <module>                    # ROP 链（若 DEP 开启）
!exploitable                             # 自动可利用率分级
```

### 3.3 DLL 劫持与搜索顺序

1. **静态**：`dumpbin /imports` 列出导入的 DLL，
   筛出**非绝对路径**、**非 KnownDLL** 的项。
2. **动态**：Procmon 过滤 `Process Name = sample.exe`、
   `Result = NAME NOT FOUND`、`Path ends with .dll`
   → 命中的就是"缺失即被劫持"的候选。
3. **构造**：把同名测试 DLL 放到搜索顺序中**可写且先于系统目录**的位置
   （通常是应用目录），触发加载。
4. **判定**：测试 DLL 被加载并执行（弹窗/写文件即可证明），
   在**授权范围内**证明即可，**不得替换系统目录中的 DLL**。

**三兄弟辨析**（报告里必须写清是哪一种）：

- **DLL 劫持**：应用自身的导入表中存在可被替代的 DLL。
- **DLL 搜索顺序劫持**：应用未指定绝对路径，加载了非预期目录中的同名 DLL。
- **Phantom DLL 劫持**：DLL 不存在，应用持续尝试加载 → 一旦目标目录可写即被执行。

### 3.4 验收标准

| 结论 | 是否可提交 |
|---|---|
| "反汇编中看到 strcpy，疑似溢出" | ❌ lead |
| "输入超长字符串导致崩溃（附崩溃转储）" | ⚠️ 需证明**可控性** |
| "EIP/RIP 被输入覆盖，可控制执行流" | ✅ finding |
| "测试 DLL 被加载并执行（附截图）" | ✅ finding（DLL 劫持） |
| "格式串可泄漏栈数据（附泄漏输出）" | ✅ finding（信息泄漏） |

> **硬要求**：崩溃类 finding 必须包含**可复现的输入**（样本/参数/触发步骤）
> 与**崩溃时的寄存器/调用栈**；仅"程序崩溃了"不足以定级。

---

## 4. 工具链

| 阶段 | 工具 |
|---|---|
| 静态结构 | `pestudio` · `PE-bear` · `CFF Explorer` · `DIE`(Detect It Easy) |
| 反汇编/反编译 | `Ghidra`（免费首选）· `IDA` · `Binary Ninja` |
| .NET | `dnSpy` · `ILSpy` · `de4dot`（反混淆） |
| 动态调试 | `x64dbg` · `WinDbg` + `mona.py` · `!exploitable` |
| 行为监控 | `Process Monitor` · `Process Hacker` · `API Monitor` |
| Hook | `Frida`（Windows 支持完善）· `Detours` |
| 字符串 | `strings`(Sysinternals) · `FLOSS`（混淆字符串） |
| 脱壳 | `upx -d` · `Scylla`（dump + IAT 修复） |

---

## 5. 与既有模块的复用

| 目标 | 复用 | 说明 |
|---|---|---|
| 线索板记录 | `clueboard.py`（hosts/paths/keys） | 记录模块基址、偏移、patch 内容 |
| 交付 | `report_docx.py` | 崩溃类走 `memory_corruption` 命门 |
| 网络行为回连验证 | `oob_client.py` | 样本外连回调可验证 |
| 越权逻辑（配置类软件） | `business_logic.py` | 授权校验缺陷仍走 A/B 口径 |

---

## 6. 合规

1. **隔离环境**：动态分析仅在快照可回滚的隔离虚拟机中进行，禁止在生产主机运行未知样本。
2. **不传播样本**：样本与反编译产物不入库、不公开、不转售。
3. **不碰系统**：DLL 劫持验证在应用目录中构造即可，**不得替换系统目录 DLL**。
4. **仅授权目标**：第三方软件未授权逆向属违规；使用公开靶场样本时遵守其许可条款。

---

结束。本手册与 `AGENTS.md`（纪律）、`references/android_audit.md`（同为二进制域）配套使用。
