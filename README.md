# Proxmox VE 9 ARM64 虚拟机 GIC 中断管理系统 (PVE GIC Manager)

本系统专为运行在 **Proxmox VE 9 (ARM64 / AArch64 架构)** 上的 QEMU 虚拟机量身定制，用于实时监控、硬件级中断版本智能推断、诊断并动态配置虚拟机中断控制器 (**GIC, Generic Interrupt Controller**) 版本。

> **背景痛点**：在飞腾、鲲鹏等 ARM64 架构物理宿主机上，QEMU 创建的 4 核 / 8 核以上虚拟机若默认分配 GICv2，会导致中断线数量超限或分发冲突，引发虚拟机开机卡在 EFI 固件 Logo（`Start boot option`）且无法进入 OS 的问题。本系统通过直观的 Web 界面与集群双向同步机制，实现 GIC 状态秒级可视与一键修复。

---

## 一、系统架构与模块设计

系统采用轻量级、无第三方重依赖的 Python 3 异步并发双服务架构，完全适配 Proxmox VE 官方技术规范：

```
+-------------------------------------------------------------------------+
|                        用户浏览器 (Web Browser)                         |
+-------------------------------------------------------------------------+
                                     |
                          HTTP 8005 (Web UI 单页应用)
                                     v
+-------------------------------------------------------------------------+
|                pve-gic-manager 前端托管与反向代理 (:8005)               |
|  - 纯原生单页架构 (SPA)，1:1 像素级复刻 Proxmox VE 9 官方 ExtJS 界面   |
|  - 支持 100% (1280x800) / 80% (1600x900) 跨分辨率无横向滚动完美适配    |
|  - 提供 Proxmox 官方 PAM/Realm 用户登录鉴权体系与 Session 会话拦截     |
+-------------------------------------------------------------------------+
                                     |
                       内部回环 / 跨节点安全通信 (Port 8004)
                                     v
+-------------------------------------------------------------------------+
|                 pve-gic-manager 集群节点 API 服务 (:8004)               |
|  - 集群节点身份认证 (Header: X-Node-Token 强校验)                       |
|  - QMP 底层运行时中断查询 (UNIX Socket: /var/run/qemu-server/<vmid>.qmp)|
|  - 关机状态智能推断引擎 (配置解析 + CPU 核心拓扑规则)                  |
|  - 虚拟机真实 IP 嗅探引擎 (QEMU Guest Agent + 宿主机网桥 ARP 探测)     |
|  - 集群操作审计历史引擎 (持久化落盘，严格仅 root 可删除)                |
|  - 后台守护监视器 (inotify 监听 /etc/pve/nodes/ 虚拟机增删事件)         |
+-------------------------------------------------------------------------+
               |                                            |
         (本地节点执行)                             (集群对端节点代理转发)
               |                                            |
    +---------------------+                      +---------------------+
    | 本地 QMP / pvesh    |                      | 远程节点 (:8004)    |
    | VM 100, 101, 102... |                      | Node 2, Node 3...   |
    +---------------------+                      +---------------------+
```

---

## 二、核心功能特性

### 1. 硬件级 GIC 版本精确标识
* **运行态中断探测**：直接连通 QEMU QMP 监控套接字读取虚拟机实际初始化的中断芯片版本（Active GIC）。
* **关机态智能推断**：解析虚拟机 `.conf` 配置文件中的 `args` 或 `machine` 参数；未显式定义时，依据 ARM64 内核规则根据核心数判定（8 核以上默认推断风险）。
* **色彩与徽标规范**：
  * **GICv3 (运行中/已配置)**：显示为**绿色徽标**，代表具备海量 SPI/LPI 现代中断能力，运行平稳。
  * **GICv2 (高风险引导隐患)**：显示为**高亮红色徽标**并伴有告警指示，提示可能存在固件引导卡死隐患。

### 2. 真实 IP 地址探测
* **双模混合探测**：优先通过 `pvesh` / QEMU Guest Agent 查询虚拟机内部网卡真实分配的 IPv4 地址；
* **ARP 邻居表自动穿透**：未安装 Guest Agent 的虚拟机，自动匹配宿主机 Linux Bridge（如 `vmbr0`）上的 ARP / Neighbor 缓存表及 MAC 映射，精准呈现各虚拟机的真实 IP。

### 3. 多视口与高低缩放比自适应
* 专为 **100% 缩放**（1280x800 典型笔记本分辨率）与 **80% 缩放**（1600x900 及以上宽屏）进行了响应式列宽精细化重构：
  * 主表格总宽度控制在 1000px 以内，`[关机]`、`[停止]`、`[重启]`、`[配置]` 四大操作按钮 100% 完整显示在当前可视区，**无需横向滚动，彻底杜绝按钮截断与遮挡**。
  * 顶栏采用弹性盒自适应布局，搜索框与状态栏保持 16px 留白间距，文字绝不折行。

### 4. 概览统计卡片视口联动
* 顶部的“虚拟机总数”、“GICv3 正常数”、“GICv2 风险数”、“已关机数”概览卡片，在左侧树切换到“数据中心”或具体“节点”时自适应计算并展示对应范围的数量；
* 点击单台虚拟机时自动收起概览卡片，进入专属虚拟机管理视角。

### 5. 操作审计历史中心 (Audit History)
* 记录集群内发生的所有开关机、重启、强制停止以及 GIC 版本变更日志（含时间、操作节点、操作用户、执行结果）；
* **安全权限隔离**：严格限制仅 `root@pam` 超级用户拥有删除/清空操作历史的权限，普通用户端按钮置灰禁用，后端拒绝未授权调用。

### 6. PVE 9 官方视觉与双主题无缝切换
* 1:1 还原 Proxmox VE 9 官方设计语言，全面移除 Emoji，采用官方矢量图标与配色；
* 支持**暗黑主题 (Dark Theme)** 与 **明亮主题 (Light Theme)** 一键切换，偏好自动持久化至浏览器 LocalStorage。

---

## 三、源码目录结构

```
PVE-PVE9中断管理web页面/
├── debian/                              # Debian 软件包打包元数据
│   ├── control                          # 软件包描述、维护者、系统架构与依赖定义
│   ├── pve-gic-manager.service          # systemd 开机自启常驻服务单元
│   ├── postinst                         # 安装后自动化脚本 (Token生成/服务注册/自动启动)
│   ├── prerm                            # 卸载前清理脚本 (停止/注销服务)
│   └── postrm                           # 卸载后资源释放脚本
├── pve_gic_manager/                     # Python 核心后端模块与静态资源
│   ├── static/                          # 前端 Web 静态资源
│   │   ├── css/
│   │   │   ├── font-awesome.min.css     # 矢量图标样式
│   │   │   └── pve-theme.css            # PVE 9 官方规范样式表 (双主题、自适应布局)
│   │   ├── fonts/                       # 离线矢量字体文件 (woff2, woff, ttf)
│   │   ├── js/
│   │   │   └── pve-gic-app.js           # 前端 SPA 业务逻辑、交互状态管理
│   │   └── index.html                   # Web 管理控制台单页主入口 (支持动态模板渲染)
│   ├── __init__.py                      # 模块声明与版本定义 (v1.0.0)
│   ├── main.py                          # 服务主入口 (统一拉起 8004 与 8005 双服务)
│   ├── config.py                        # 全局配置管理与集群共享 Token 读写
│   ├── auth_handler.py                  # PVE 原生 PAM 认证验证与 Session 管理
│   ├── cluster_auth.py                  # 节点间 Token 认证与签名算法
│   ├── history_manager.py               # 操作历史审计引擎 (数据落盘与 RBAC 鉴权)
│   ├── pve_scanner.py                   # GIC 中断探测器、ARP 扫描与动态系统版本提取
│   ├── api_service.py                   # 节点间 RESTful API 服务 (端口 8004)
│   └── web_service.py                   # 前端静态托管与 API 反向代理服务 (端口 8005)
├── build_deb.py                         # 跨平台无外部依赖的 Debian 打包工具 (纯 Python 实现)
├── pve-gic-manager                      # Linux 宿主机可执行命令行启动入口 (/usr/bin)
├── Makefile                             # 标准工程构建脚本
└── README.md                            # 官方中文使用与开发指南
```

---

## 四、构建与打包指南

本项目自带跨平台纯 Python 实现的 debian 打包器 [`build_deb.py`](build_deb.py)，**无需在 Linux 环境或安装 `dpkg-deb` 工具**，在 Windows、macOS 或 Linux 环境下均可一键完成打包。

### 1. 构建前置条件
* **Python 3.8+**（无需额外安装外部依赖库，标准库即可运行）

### 2. 执行打包
在项目根目录下执行以下任一命令：

* **方式 A：通过 Python 脚本打包（推荐，跨平台通用）**：
  ```bash
  python build_deb.py
  ```

* **方式 B：通过 Makefile 打包（Linux / WSL 环境）**：
  ```bash
  make deb
  ```

### 3. 构建输出
打包成功后，将在当前项目根目录生成标准的 Debian 安装包：
```
pve-gic-manager_1.0.0_all.deb
```
包体大小约 340 KB，内部已封装完整的二进制入口、Python 模块、编译完成的前端样式、离线图标字体库以及 systemd 服务注册文件。

---

## 五、在 PVE 集群中的安装与部署

### 1. 分发安装包
将生成的 `pve-gic-manager_1.0.0_all.deb` 上传至集群内各 PVE 节点（如 `/root/` 目录）：
```bash
scp pve-gic-manager_1.0.0_all.deb root@<PVE-NODE-IP>:/root/
```

### 2. 执行安装
在每个节点终端执行安装命令：
```bash
dpkg -i /root/pve-gic-manager_1.0.0_all.deb
```

> **安装脚本自动处理的事项**：
> 1. 创建配置目录 `/etc/pve-gic-manager/`；
> 2. 自动检测 `/etc/pve/` 集群分布式文件系统，生成并全集群同步加密通信 Token；
> 3. 安装服务单元 `/etc/systemd/system/pve-gic-manager.service`；
> 4. 执行 `systemctl daemon-reload` 并开机自启启动服务。

### 3. 端口防火墙放行（如开启了 PVE 防火墙）
* **8005 端口**：Web UI 管理界面，允许管理员电脑或内网访问。
* **8004 端口**：节点间通信 API，需确保 PVE 各节点互通。

---

## 六、日常运维与服务管理

在已安装的 PVE 宿主机上，可通过系统标准命令进行运维：

```bash
# 检查服务运行状态
systemctl status pve-gic-manager.service

# 查看服务实时运行日志
journalctl -u pve-gic-manager.service -f -n 50

# 重启管理服务
systemctl restart pve-gic-manager.service

# 停止管理服务
systemctl stop pve-gic-manager.service
```

### 卸载与清理
如需彻底卸载软件：
```bash
dpkg -r pve-gic-manager
```
卸载程序会自动停止并注销 systemd 服务，释放对应端口。

---

## 七、RESTful API 接口速查 (Port 8004)

节点间及内部通信支持标准 RESTful JSON 接口（跨节点调用需携带 Header `X-Node-Token: <CLUSTER_TOKEN>`）：

| 接口路径 | 方法 | 鉴权要求 | 说明 |
| :--- | :--- | :--- | :--- |
| `/api/v1/version` | `GET` | 公开 | 获取当前宿主机的真实 PVE 系统版本（如 `9.2.9`）及内核版本 |
| `/api/v1/login` | `POST` | 公开 | 用户认证登录接口（校验 PAM 用户名及密码，下发 session） |
| `/api/v1/vms` | `GET` | 需认证 | 获取当前节点（或代理全集群）的虚拟机中断状态与真实 IP 列表 |
| `/api/v1/nodes` | `GET` | 需认证 | 获取当前集群内各节点名称、在线状态及管理 IP |
| `/api/v1/sync` | `POST` | 需认证 | 触发主动全量重新扫描与 ARP 刷新 |
| `/api/v1/vm/<vmid>/gic` | `POST` | 需认证 | 更新指定虚拟机的 GIC 版本（`{"gic_version": "gicv3"}`） |
| `/api/v1/vm/<vmid>/power` | `POST` | 需认证 | 执行电源操作（支持 `start`、`shutdown`、`stop`、`reboot`） |
| `/api/v1/history` | `GET` | 需认证 | 获取全局操作审计历史列表 |
| `/api/v1/history/delete` | `POST` | 仅 root | 删除指定的审计记录或清空历史（普通用户拒绝） |

---

## 八、开源许可证与维护

* **维护团队**：Phytium Virtualization Team
* **适用平台**：Proxmox VE 8.x / 9.x (ARM64 / AArch64)
* **授权协议**：MIT License
