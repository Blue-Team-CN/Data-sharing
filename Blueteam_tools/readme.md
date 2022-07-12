# Blueteam_tools

## 说明

本项目主要收集攻防演练中一些常见的蓝队工具，相关程序文件在本项目中可以下载到，也可以通过跳转至开发者项目下载，其安全性自行测试，不做保证，出现问题概不负责。

## 工具集

### Shiro反序列化数据包解密及蓝队分析工具

[下载地址](https://mp.weixin.qq.com/s/5VQ4KHrgFDzkif3bcVAIcA)

### CobaltStrikeScan

扫描文件或进程内存以查找Cobalt Strike信标并解析其配置。

CobaltStrikeScan扫描Windows进程内存以查找DLL注入（经典或反射注入）的证据和/或对目标进程的内存执行YARA扫描以获取Cobalt Strike v3和v4信标签名。

或者，CobaltStrikeScan可以对由绝对或相对路径作为命令行参数提供的文件执行相同的YARA扫描。

如果在文件或进程中检测到Cobalt Strike信标，则信标的配置将被解析并显示到控制台。

[下载地址](https://github.com/Apr4h/CobaltStrikeScan)

### DuckMemoryScan

一个简单寻找包括不限于iis劫持,无文件木马,shellcode免杀后门的工具,由huoji花了1天编写,编写时间2021-02-24 !!!本程序需要64位编译才能回溯x64的程序堆栈,请勿执行32位编译!!! !!!本工具不能代替杀毒软件!!!

功能列表

- HWBP hook检测 检测线程中所有疑似被hwbp隐形挂钩
- 内存免杀shellcode检测(metasploit，Cobaltstrike完全检测)
- 可疑进程检测(主要针对有逃避性质的进程[如过期签名与多各可执行区段])
- 无文件落地木马检测(检测所有已知内存加载木马)
- 简易rootkit检测(检测证书过期/拦截读取/证书无效的驱动)
- 检测异常模块,检测绝大部分如"iis劫持"的后门(2021年2月26日新增)

注意：可绕过，[参考文章-蹭热点之绕过DuckMemoryScan](https://cloud.tencent.com/developer/article/1808207)

[下载地址](https://github.com/huoji120/DuckMemoryScan)

### LiqunShield:Webshell流量解密

该工具制作初衷是个人研究webshell管理工具时为方便个人对流量分析突发奇想而为。

目前支持哥斯拉载荷的解密如下：

- CsharpAesBase64
- PhpEvalXorBase64（该载荷解密数据为key中的内容，而不是pass的，key中内容才是传输的加密内容）
- PhpXorBase64
- JavaAesBase64
- JavaAesRaw（该解密目前只支持请求包解密，且流量需要16进制数据，可通过wireshark抓取）
- AspEvalBase64
- AspXorBase64
- AspBase64
- CsharpAsmxAesBase64
- CsharpEvalAesBase64

由于作者删除了github项目，故无下载地址。

### BlueHound

BlueHound 是一款GUI版本主机威胁狩猎工具。支持上机/离线扫描webshell、CobaltStrike的beacon程序扫描以及内存扫描，基于.NET 4.6编译。

[下载地址](https://github.com/10000Tigers/BlueHound)
