/**
 * Proxmox VE 9.2.9 GIC Management App
 * Features:
 *  1. PVE Official Vector Icons (Matching PVE Desktop UI)
 *  2. GICv2 (Red) & GICv3 (Green) identical fixed width & tags
 *  3. Stopped VMs also highlighted with Red/Green GIC tags
 *  4. Strict PVE User Authentication (Login Modal against PVE PAM/Realm)
 */

const AppState = {
    nodes: {},
    vms: {},
    clusterName: "",
    localNode: "",
    localIp: "",
    selectedNode: null,
    selectedVmId: null,
    selectedVmIds: new Set(),
    searchQuery: "",
    isSyncing: false,
    lastSyncTime: null,
    taskLogs: [],
    currentTheme: "dark",
    currentUser: null
};

// Official PVE FontAwesome Icons (Matching PVE 9 ExtJS UI)
const PVEIcons = {
    datacenter: `<i class="x-tree-icon x-tree-icon-custom fa fa-server"></i>`,
    node: `<i class="x-tree-icon x-tree-icon-custom fa fa-building online"></i>`,
    vmRunning: `<i class="x-tree-icon x-tree-icon-custom fa fa-desktop running"></i>`,
    vmStopped: `<i class="x-tree-icon x-tree-icon-custom fa fa-desktop stopped"></i>`
};

document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initSplitters();
    initUI();
    initDefaultTasks();

    // Dynamically fetch and display live host PVE version
    fetchSystemVersion();

    // Check PVE User Authentication (Requirement 4)
    checkAuthAndInit();
});

function updatePveVersionLabel(version) {
    const valEl = document.getElementById("pve-version-val");
    if (valEl && version) {
        valEl.textContent = version;
    } else {
        const el = document.getElementById("pve-version-tag");
        if (el && version) {
            el.textContent = `Virtual Environment ${version} | GIC 管理器`;
        }
    }
}

async function fetchSystemVersion() {
    try {
        const resp = await fetch("/api/v1/version");
        if (resp.ok) {
            const data = await resp.json();
            if (data && data.version) {
                updatePveVersionLabel(data.version);
                console.log(`%c[PVE System] 动态探测当前宿主机系统版本: PVE ${data.version} (内核: ${data.kernel || '默认'})`, "color: #2ecc71; font-weight: bold;");
            }
        }
    } catch (e) {
        console.debug("Failed to fetch /api/v1/version:", e);
    }
}

/**
 * Check if user is authenticated against PVE API
 */
async function checkAuthAndInit() {
    try {
        const resp = await fetch("/api/v1/auth/status");
        const data = await resp.json();
        if (data.pve_version) {
            updatePveVersionLabel(data.pve_version);
        }
        if (data.authenticated && data.username) {
            AppState.currentUser = data.username;
            AppState.localNode = data.local_node || "";
            AppState.localIp = data.local_ip || "";
            document.getElementById("user-display").textContent = data.username;
            document.getElementById("pve-login-modal").style.display = "none";
            // Start cluster discovery
            performScan(true);
            setupHeartbeats();
        } else {
            showLoginModal();
        }
    } catch (e) {
        showLoginModal();
    }
}

function showLoginModal() {
    const modal = document.getElementById("pve-login-modal");
    modal.style.display = "flex";
    document.getElementById("login-password").value = "";
    document.getElementById("login-error").textContent = "";
    document.getElementById("login-password").focus();
}

function setupHeartbeats() {
    // Auto-rescan when switching back to tab (Requirement 8)
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden && AppState.currentUser) {
            performScan(false);
        }
    });

    // Periodic heartbeat sync every 15s
    setInterval(() => {
        if (!document.hidden && !AppState.isSyncing && AppState.currentUser) {
            fetchVMData();
        }
    }, 15000);
}

function initTheme() {
    const savedTheme = localStorage.getItem("pve_theme") || "dark";
    setTheme(savedTheme, false);

    const btnToggle = document.getElementById("btn-theme-toggle");
    if (btnToggle) {
        btnToggle.addEventListener("click", () => {
            const nextTheme = AppState.currentTheme === "dark" ? "light" : "dark";
            setTheme(nextTheme, true);
        });
    }
}

function setTheme(theme, logAction = false) {
    AppState.currentTheme = theme;
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("pve_theme", theme);

    const themeIcon = document.getElementById("theme-icon");
    const themeText = document.getElementById("theme-text");
    if (themeIcon && themeText) {
        if (theme === "dark") {
            themeIcon.textContent = "🌙";
            themeText.textContent = "暗黑主题";
        } else {
            themeIcon.textContent = "☀️";
            themeText.textContent = "白色主题";
        }
    }

    if (logAction) {
        addTaskLog(`切换界面风格为: ${theme === 'dark' ? '暗黑主题' : '白色主题'}`, "OK");
    }
}

/* ==========================================================================
   Message Center Manager (Requirement 2)
   ========================================================================== */
class MessageCenter {
    static STORAGE_KEY = "pve_gic_messages_v1";
    static currentFilter = "all";

    static getAll() {
        try {
            const raw = localStorage.getItem(MessageCenter.STORAGE_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch (e) {
            return [];
        }
    }

    static save(messages) {
        try {
            if (messages.length > 100) messages = messages.slice(0, 100);
            localStorage.setItem(MessageCenter.STORAGE_KEY, JSON.stringify(messages));
            MessageCenter.render();
        } catch (e) {
            console.error("MessageCenter save error:", e);
        }
    }

    static add(item) {
        const messages = MessageCenter.getAll();
        const now = new Date();
        const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
        
        // Discover operator user
        const operator = item.user || AppState.currentUser || "root@pam";
        
        // Discover origin source node
        let sourceNode = item.source_node || AppState.localNode || "";
        if (!sourceNode) {
            const host = window.location.hostname;
            for (const [nName, nInfo] of Object.entries(AppState.nodes || {})) {
                if (nInfo.ip === host) {
                    sourceNode = nName;
                    break;
                }
            }
            if (!sourceNode) {
                sourceNode = host || "pve";
            }
        }
        
        const targetNode = item.target_node || item.node || "";

        const newMsg = {
            id: item.id || `msg_${Date.now()}_${Math.floor(Math.random()*1000)}`,
            time: timeStr,
            timestamp: Date.now(),
            user: operator,
            source_node: sourceNode,
            target_node: targetNode,
            vmid: item.vmid,
            vm_name: item.vm_name || (item.vmid ? `VM ${item.vmid}` : ""),
            node: targetNode,
            action: item.action || "",
            action_name: item.action_name || "",
            status: item.status || "in_progress", // in_progress | success | warning | error
            title: item.title || "",
            detail: item.detail || "",
            is_exception: !!item.is_exception,
            can_force_stop: !!item.can_force_stop,
            unread: true
        };
        messages.unshift(newMsg);
        MessageCenter.save(messages);
        return newMsg.id;
    }

    static update(id, updates) {
        const messages = MessageCenter.getAll();
        const idx = messages.findIndex(m => m.id === id);
        if (idx !== -1) {
            messages[idx] = { ...messages[idx], ...updates };
            MessageCenter.save(messages);
        }
    }

    static remove(id) {
        let messages = MessageCenter.getAll();
        messages = messages.filter(m => m.id !== id);
        try {
            localStorage.setItem(MessageCenter.STORAGE_KEY, JSON.stringify(messages));
        } catch(e) {}
        MessageCenter.render();
    }

    static clear() {
        localStorage.removeItem(MessageCenter.STORAGE_KEY);
        MessageCenter.render();
    }

    static markAllRead() {
        const messages = MessageCenter.getAll();
        messages.forEach(m => m.unread = false);
        try {
            localStorage.setItem(MessageCenter.STORAGE_KEY, JSON.stringify(messages));
        } catch(e){}
        MessageCenter.render();
    }

    static render(filter = null) {
        if (filter !== null) {
            MessageCenter.currentFilter = filter;
        }
        const activeFilter = MessageCenter.currentFilter;
        const messages = MessageCenter.getAll();
        const listEl = document.getElementById("message-center-list");
        const badgeEl = document.getElementById("msg-center-badge");
        const allCountEl = document.getElementById("msg-all-count");
        const excCountEl = document.getElementById("msg-exception-count");

        const unreadCount = messages.filter(m => m.unread).length;
        const exceptionCount = messages.filter(m => m.status === "warning" || m.status === "error").length;

        if (allCountEl) allCountEl.textContent = messages.length;
        if (excCountEl) excCountEl.textContent = exceptionCount;

        if (badgeEl) {
            if (unreadCount > 0) {
                badgeEl.textContent = unreadCount > 99 ? "99+" : unreadCount;
                badgeEl.style.display = "inline-block";
                badgeEl.style.backgroundColor = exceptionCount > 0 ? "#dc3545" : "#e57000";
            } else {
                badgeEl.style.display = "none";
            }
        }

        if (!listEl) return;

        let displayList = messages;
        if (activeFilter === "exceptions") {
            displayList = messages.filter(m => m.status === "warning" || m.status === "error");
        }

        if (displayList.length === 0) {
            listEl.innerHTML = `
                <div class="empty-msg-notice" style="text-align: center; color: var(--pve-text-muted); padding: 35px 10px; font-size: 12px;">
                    <i class="fa fa-inbox fa-2x" style="opacity: 0.5; margin-bottom: 8px; display: block;"></i>
                    ${activeFilter === 'exceptions' ? '暂无异常或告警消息' : '暂无操作记录'}
                </div>
            `;
            return;
        }

        listEl.innerHTML = displayList.map(msg => {
            let statusBadge = "";
            let cardBorderClass = "";
            if (msg.status === "in_progress") {
                statusBadge = `<span class="msg-status-pill in-progress"><i class="fa fa-spinner spin-anim"></i> 进行中</span>`;
                cardBorderClass = "border-in-progress";
            } else if (msg.status === "success") {
                statusBadge = `<span class="msg-status-pill success"><i class="fa fa-check-circle"></i> 成功</span>`;
                cardBorderClass = "border-success";
            } else if (msg.status === "warning") {
                statusBadge = `<span class="msg-status-pill warning"><i class="fa fa-exclamation-triangle"></i> 需人工介入</span>`;
                cardBorderClass = "border-warning";
            } else {
                statusBadge = `<span class="msg-status-pill error"><i class="fa fa-times-circle"></i> 失败</span>`;
                cardBorderClass = "border-error";
            }

            let actionBadge = `<span class="msg-action-tag">${escapeHtml(msg.action_name || msg.action)}</span>`;

            let forceStopBtn = "";
            if (msg.can_force_stop && msg.status === "warning") {
                forceStopBtn = `
                    <div style="margin-top: 8px; text-align: right;">
                        <button class="pve-btn pve-btn-xs pve-btn-danger btn-inline-force-stop" data-vmid="${msg.vmid}" data-node="${msg.node}" style="padding: 2px 10px; font-size: 11px; height: 22px;">
                            <i class="fa fa-stop"></i> 立即强制停止 (推荐)
                        </button>
                    </div>
                `;
            }

            const operator = msg.user || "root@pam";
            const sourceNode = msg.source_node || "pve";
            const targetNode = msg.target_node || msg.node || "-";

            return `
                <div class="msg-card ${cardBorderClass}" data-id="${msg.id}">
                    <div class="msg-card-header">
                        <div class="msg-card-title">
                            ${actionBadge}
                            <strong>${escapeHtml(msg.vm_name || (msg.vmid ? 'VM ' + msg.vmid : '集群操作'))}</strong>
                            ${targetNode && targetNode !== '-' ? `<span class="msg-node-tag">(${escapeHtml(targetNode)})</span>` : ''}
                        </div>
                        <div class="msg-header-right">
                            ${statusBadge}
                            <span class="msg-time">${msg.time}</span>
                            <button class="btn-msg-delete" data-id="${msg.id}" title="删除此条记录">
                                <i class="fa fa-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="msg-card-meta">
                        <span class="meta-item"><i class="fa fa-user"></i> 操作人: <strong>${escapeHtml(operator)}</strong></span>
                        <span class="meta-sep">|</span>
                        <span class="meta-item"><i class="fa fa-paper-plane"></i> 发起: <strong>${escapeHtml(sourceNode)}</strong></span>
                        ${targetNode && targetNode !== '-' ? `
                            <span class="meta-arrow">→</span>
                            <span class="meta-item"><i class="fa fa-server"></i> 目标: <strong>${escapeHtml(targetNode)}</strong></span>
                        ` : ''}
                    </div>
                    <div class="msg-card-body">
                        ${escapeHtml(msg.detail || msg.title)}
                    </div>
                    ${forceStopBtn}
                </div>
            `;
        }).join("");

        // Attach event listeners to individual delete buttons
        listEl.querySelectorAll(".btn-msg-delete").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const id = btn.dataset.id;
                MessageCenter.remove(id);
            });
        });

        // Attach event listeners to inline force stop buttons
        listEl.querySelectorAll(".btn-inline-force-stop").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const vmid = parseInt(btn.dataset.vmid);
                const node = btn.dataset.node;
                executePowerAction(vmid, node, "stop");
            });
        });
    }
}

/* ==========================================================================
   Operation Audit History Manager (Requirement Turn 12)
   Server-side persistent audit history with strict RBAC (only root can delete)
   ========================================================================== */
class HistoryManager {
    static records = [];
    static isRoot = false;
    static currentUser = "root@pam";
    static searchQuery = "";
    static statusFilter = "all";

    static async fetchHistory() {
        try {
            const resp = await fetch("/api/v1/history?limit=300");
            const data = await resp.json();
            if (data.success) {
                HistoryManager.records = data.history || [];
                HistoryManager.isRoot = !!data.is_root;
                HistoryManager.currentUser = data.current_user || AppState.currentUser || "root@pam";
                HistoryManager.updateUserPill();
                HistoryManager.renderTable();
                HistoryManager.renderConsoleHistory();
            }
        } catch (e) {
            console.error("fetchHistory failed:", e);
        }
    }

    static updateUserPill() {
        const pill = document.getElementById("history-user-pill");
        const text = document.getElementById("history-user-text");
        const clearBtn = document.getElementById("btn-clear-all-history");
        const isRoot = HistoryManager.isRoot;

        if (pill && text) {
            pill.className = `user-permission-pill ${isRoot ? 'root' : 'non-root'}`;
            text.textContent = isRoot 
                ? `当前操作者: ${HistoryManager.currentUser} (超级管理员，具备删除权限)`
                : `当前操作者: ${HistoryManager.currentUser} (普通用户，仅只读查看)`;
        }

        if (clearBtn) {
            clearBtn.disabled = !isRoot;
            clearBtn.title = isRoot 
                ? "清空全部操作历史记录 (不可恢复)"
                : "权限不足：仅 root 用户具备清空审计历史权限";
            clearBtn.style.opacity = isRoot ? "1" : "0.4";
            clearBtn.style.cursor = isRoot ? "pointer" : "not-allowed";
        }
    }

    static renderTable() {
        const tbody = document.getElementById("history-table-body");
        if (!tbody) return;

        let filtered = HistoryManager.records;
        if (HistoryManager.statusFilter !== "all") {
            filtered = filtered.filter(r => r.status === HistoryManager.statusFilter);
        }
        if (HistoryManager.searchQuery) {
            const q = HistoryManager.searchQuery.toLowerCase();
            filtered = filtered.filter(r => {
                return (r.time && r.time.toLowerCase().includes(q)) ||
                       (r.user && r.user.toLowerCase().includes(q)) ||
                       (r.source_node && r.source_node.toLowerCase().includes(q)) ||
                       (r.target_node && r.target_node.toLowerCase().includes(q)) ||
                       (String(r.vmid || '').includes(q)) ||
                       (r.vm_name && r.vm_name.toLowerCase().includes(q)) ||
                       (r.action_desc && r.action_desc.toLowerCase().includes(q)) ||
                       (r.detail && r.detail.toLowerCase().includes(q));
            });
        }

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--pve-text-muted); padding: 30px;">暂无匹配的操作审计历史记录</td></tr>`;
            return;
        }

        const isRoot = HistoryManager.isRoot;
        tbody.innerHTML = filtered.map(r => {
            let stClass = "ok";
            let stText = "成功";
            if (r.status === "ERROR") {
                stClass = "error";
                stText = "失败";
            } else if (r.status === "WARN" || r.status === "warning") {
                stClass = "warn";
                stText = "警告";
            } else if (r.status === "IN_PROGRESS") {
                stClass = "warn";
                stText = "执行中";
            }

            const delBtnHtml = isRoot
                ? `<button class="btn-history-del" onclick="HistoryManager.deleteItem('${r.id}')" title="删除该条历史记录"><i class="fa fa-trash"></i></button>`
                : `<button class="btn-history-del" disabled title="权限不足：仅 root 用户允许删除记录"><i class="fa fa-trash"></i></button>`;

            const vmLabel = r.vmid ? `<strong>${r.vmid}</strong> (${escapeHtml(r.vm_name || '')})` : (r.vm_name || '-');
            const nodeFlow = `${escapeHtml(r.source_node || '-')} <span style="color:var(--pve-primary-orange);font-weight:bold;">&rarr;</span> ${escapeHtml(r.target_node || '-')}`;

            return `
                <tr>
                    <td style="color: var(--pve-text-muted); font-size: 11px;">${escapeHtml(r.time || '')}</td>
                    <td><strong>${escapeHtml(r.user || 'root@pam')}</strong></td>
                    <td>${nodeFlow}</td>
                    <td>${vmLabel}</td>
                    <td><span style="font-weight: 500;">${escapeHtml(r.action_desc || r.action || '')}</span></td>
                    <td><span class="history-status-badge ${stClass}">${stText}</span></td>
                    <td style="max-width: 320px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(r.detail || '')}">${escapeHtml(r.detail || '')}</td>
                    <td style="text-align: center;">${delBtnHtml}</td>
                </tr>
            `;
        }).join("");
    }

    static renderConsoleHistory() {
        const tbody = document.getElementById("console-history-body");
        if (!tbody) return;

        const records = HistoryManager.records.slice(0, 50);
        if (records.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--pve-text-muted); padding: 15px;">暂无操作审计历史记录</td></tr>`;
            return;
        }

        tbody.innerHTML = records.map(r => {
            let stColor = "#27ae60";
            let stText = "OK";
            if (r.status === "ERROR") {
                stColor = "#e74c3c";
                stText = "ERROR";
            } else if (r.status === "WARN" || r.status === "warning") {
                stColor = "#f39c12";
                stText = "WARN";
            }

            const vmLabel = r.vmid ? `VM ${r.vmid}` : (r.vm_name || '-');
            const nodeFlow = `${escapeHtml(r.source_node || '-')} &rarr; ${escapeHtml(r.target_node || '-')}`;

            return `
                <tr>
                    <td style="color: var(--pve-text-muted); font-size: 11px;">${escapeHtml(r.time || '')}</td>
                    <td><strong>${escapeHtml(r.user || 'root@pam')}</strong></td>
                    <td>${nodeFlow}</td>
                    <td><strong>${vmLabel}</strong></td>
                    <td>${escapeHtml(r.action_desc || r.action || '')}</td>
                    <td><span style="color: ${stColor}; font-weight: bold;">${stText}</span></td>
                    <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(r.detail || '')}">${escapeHtml(r.detail || '')}</td>
                </tr>
            `;
        }).join("");
    }

    static async deleteItem(recordId) {
        if (!HistoryManager.isRoot) {
            showToastMessage("权限拒绝：仅 root@pam 超级管理员具备删除历史记录的权限！", true);
            return;
        }
        if (!confirm("确定要删除这条操作审计历史记录吗？")) return;

        try {
            const resp = await fetch("/api/v1/history/delete", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ id: recordId })
            });
            const res = await resp.json();
            if (res.success) {
                showToastMessage("操作审计历史记录已成功删除");
                await HistoryManager.fetchHistory();
            } else {
                showToastMessage("删除失败: " + (res.error || "未知原因"), true);
            }
        } catch (e) {
            showToastMessage("请求失败: " + e.message, true);
        }
    }

    static async clearAll() {
        if (!HistoryManager.isRoot) {
            showToastMessage("权限拒绝：仅 root@pam 超级管理员具备清空全部历史记录的权限！", true);
            return;
        }
        if (!confirm("【警告】清空后所有操作审计历史记录将从磁盘彻底删除且不可恢复！\n\n确定要清空全部历史记录吗？")) return;

        try {
            const resp = await fetch("/api/v1/history/delete", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ id: "all" })
            });
            const res = await resp.json();
            if (res.success) {
                showToastMessage("全部操作审计历史记录已清空");
                await HistoryManager.fetchHistory();
            } else {
                showToastMessage("清空失败: " + (res.error || "未知原因"), true);
            }
        } catch (e) {
            showToastMessage("请求失败: " + e.message, true);
        }
    }
}
window.HistoryManager = HistoryManager;

function initUI() {
    // Message Center Drawer Open / Close / Clear (Requirement 2)
    const btnMsgCenter = document.getElementById("btn-message-center");
    const drawerMsgCenter = document.getElementById("message-center-drawer");
    const btnCloseDrawer = document.getElementById("btn-close-msg-drawer");
    const btnClearMessages = document.getElementById("btn-clear-messages");
    const tabMsgAll = document.getElementById("tab-msg-all");
    const tabMsgExceptions = document.getElementById("tab-msg-exceptions");

    if (btnMsgCenter && drawerMsgCenter) {
        btnMsgCenter.addEventListener("click", () => {
            const isHidden = drawerMsgCenter.style.display === "none";
            drawerMsgCenter.style.display = isHidden ? "flex" : "none";
            if (isHidden) {
                MessageCenter.markAllRead();
                MessageCenter.render();
            }
        });
    }

    if (btnCloseDrawer && drawerMsgCenter) {
        btnCloseDrawer.addEventListener("click", () => {
            drawerMsgCenter.style.display = "none";
        });
    }

    if (btnClearMessages) {
        btnClearMessages.addEventListener("click", () => {
            if (confirm("确定要清空全部消息记录吗？")) {
                MessageCenter.clear();
                showToastMessage("已清空消息中心历史记录");
            }
        });
    }

    if (tabMsgAll && tabMsgExceptions) {
        tabMsgAll.addEventListener("click", () => {
            tabMsgAll.classList.add("active");
            tabMsgExceptions.classList.remove("active");
            MessageCenter.render("all");
        });
        tabMsgExceptions.addEventListener("click", () => {
            tabMsgExceptions.classList.add("active");
            tabMsgAll.classList.remove("active");
            MessageCenter.render("exceptions");
        });
    }

    // Initial render of Message Center
    MessageCenter.render();

    // Operation Audit History Dialog & Toolbar Events (Requirement Turn 12)
    const btnOpenHistory = document.getElementById("btn-open-history");
    const modalHistory = document.getElementById("history-modal");
    const btnCloseHistory = document.getElementById("btn-close-history-modal");
    const btnRefreshHistory = document.getElementById("btn-refresh-history");
    const btnClearAllHistory = document.getElementById("btn-clear-all-history");
    const historyFilter = document.getElementById("history-filter");
    const historyStatusFilter = document.getElementById("history-status-filter");

    if (btnOpenHistory && modalHistory) {
        btnOpenHistory.addEventListener("click", () => {
            modalHistory.style.display = "flex";
            HistoryManager.fetchHistory();
        });
    }
    if (btnCloseHistory && modalHistory) {
        btnCloseHistory.addEventListener("click", () => {
            modalHistory.style.display = "none";
        });
    }
    if (modalHistory) {
        modalHistory.addEventListener("click", (e) => {
            if (e.target === modalHistory) modalHistory.style.display = "none";
        });
    }
    if (btnRefreshHistory) {
        btnRefreshHistory.addEventListener("click", () => {
            HistoryManager.fetchHistory();
            showToastMessage("审计历史记录已刷新");
        });
    }
    if (btnClearAllHistory) {
        btnClearAllHistory.addEventListener("click", () => {
            HistoryManager.clearAll();
        });
    }
    if (historyFilter) {
        historyFilter.addEventListener("input", (e) => {
            HistoryManager.searchQuery = e.target.value.trim();
            HistoryManager.renderTable();
        });
    }
    if (historyStatusFilter) {
        historyStatusFilter.addEventListener("change", (e) => {
            HistoryManager.statusFilter = e.target.value;
            HistoryManager.renderTable();
        });
    }

    // Console Tabs (中断管理任务日志 vs 操作审计历史)
    const tabConsoleTasks = document.getElementById("tab-console-tasks");
    const tabConsoleHistory = document.getElementById("tab-console-history");
    const viewConsoleTasks = document.getElementById("console-tasks-view");
    const viewConsoleHistory = document.getElementById("console-history-view");

    if (tabConsoleTasks && tabConsoleHistory) {
        tabConsoleTasks.addEventListener("click", () => {
            tabConsoleTasks.classList.add("active");
            tabConsoleHistory.classList.remove("active");
            if (viewConsoleTasks) viewConsoleTasks.style.display = "block";
            if (viewConsoleHistory) viewConsoleHistory.style.display = "none";
        });
        tabConsoleHistory.addEventListener("click", () => {
            tabConsoleHistory.classList.add("active");
            tabConsoleTasks.classList.remove("active");
            if (viewConsoleTasks) viewConsoleTasks.style.display = "none";
            if (viewConsoleHistory) viewConsoleHistory.style.display = "block";
            HistoryManager.fetchHistory();
        });
    }

    // Initial fetch of audit history for bottom console
    HistoryManager.fetchHistory();
    // Login Form Submit (Requirement 4)
    const loginForm = document.getElementById("pve-login-form");
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("login-username").value.trim();
        const password = document.getElementById("login-password").value;
        const realm = document.getElementById("login-realm").value;
        const errEl = document.getElementById("login-error");
        errEl.textContent = "正在验证...";

        try {
            const resp = await fetch("/api/v1/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, realm })
            });
            const res = await resp.json();
            if (res.success) {
                AppState.currentUser = res.username;
                AppState.localNode = res.local_node || "";
                AppState.localIp = res.local_ip || "";
                document.getElementById("user-display").textContent = res.username;
                document.getElementById("pve-login-modal").style.display = "none";
                addTaskLog(`用户 ${res.username} 成功登录系统`, "OK");
                performScan(true);
                setupHeartbeats();
            } else {
                errEl.textContent = res.error || "认证失败，请重试";
            }
        } catch (err) {
            errEl.textContent = "网络异常或连接超时: " + err.message;
        }
    });

    // Logout
    document.getElementById("btn-logout").addEventListener("click", async () => {
        try {
            await fetch("/api/v1/auth/logout", { method: "POST" });
        } catch(e){}
        AppState.currentUser = null;
        showLoginModal();
    });

    // Sync Buttons
    document.getElementById("btn-sync-all").addEventListener("click", () => performScan(true));
    document.getElementById("btn-toolbar-sync").addEventListener("click", () => performScan(true));

    // Batch Action Buttons (GIC)
    document.getElementById("btn-batch-gic3").addEventListener("click", () => openBatchModal("3"));
    document.getElementById("btn-batch-gic2").addEventListener("click", () => openBatchModal("2"));
    document.getElementById("btn-batch-custom").addEventListener("click", () => openBatchModal("host"));

    // Batch Action Buttons (Power)
    const btnBatchStart = document.getElementById("btn-batch-power-start");
    if (btnBatchStart) btnBatchStart.addEventListener("click", () => promptBatchPowerAction("start"));

    const btnBatchShutdown = document.getElementById("btn-batch-power-shutdown");
    if (btnBatchShutdown) btnBatchShutdown.addEventListener("click", () => promptBatchPowerAction("shutdown"));

    const btnBatchStop = document.getElementById("btn-batch-power-stop");
    if (btnBatchStop) btnBatchStop.addEventListener("click", () => promptBatchPowerAction("stop"));

    const btnBatchReboot = document.getElementById("btn-batch-power-reboot");
    if (btnBatchReboot) btnBatchReboot.addEventListener("click", () => promptBatchPowerAction("reboot"));

    // Power Confirmation Modal Confirm & Cancel
    const btnPowerConfirm = document.getElementById("btn-power-modal-confirm");
    if (btnPowerConfirm) {
        btnPowerConfirm.addEventListener("click", () => {
            if (powerModalContext.isBatch) {
                submitBatchPowerAction();
            } else if (powerModalContext.vmid && powerModalContext.action) {
                closePowerModal();
                executePowerAction(powerModalContext.vmid, powerModalContext.node, powerModalContext.action);
            }
        });
    }

    document.querySelectorAll(".power-modal-cancel").forEach(btn => {
        btn.addEventListener("click", closePowerModal);
    });

    document.querySelectorAll(".suggest-stop-cancel").forEach(btn => {
        btn.addEventListener("click", closeSuggestStopModal);
    });

    const btnSuggestStopConfirm = document.getElementById("btn-suggest-stop-confirm");
    if (btnSuggestStopConfirm) {
        btnSuggestStopConfirm.addEventListener("click", () => {
            const ctx = suggestStopContext;
            closeSuggestStopModal();
            if (ctx && ctx.vmid) {
                executePowerAction(ctx.vmid, ctx.node, "stop");
            }
        });
    }

    // Search and Table Filter
    const filterInput = document.getElementById("table-filter");
    filterInput.addEventListener("input", (e) => {
        AppState.searchQuery = e.target.value.trim().toLowerCase();
        renderVMTable();
    });

    const headerSearch = document.getElementById("header-search");
    headerSearch.addEventListener("input", (e) => {
        filterInput.value = e.target.value;
        AppState.searchQuery = e.target.value.trim().toLowerCase();
        renderVMTable();
    });

    // Root Datacenter tree item click
    document.getElementById("tree-root-item").addEventListener("click", () => {
        navigateToDatacenter();
    });

    // Select All Checkbox
    document.getElementById("select-all-checkbox").addEventListener("change", (e) => {
        const checked = e.target.checked;
        const visibleVms = getFilteredVMs();
        if (checked) {
            visibleVms.forEach(vm => AppState.selectedVmIds.add(vm.vmid));
        } else {
            AppState.selectedVmIds.clear();
        }
        renderVMTable();
        updateToolbarButtons();
    });

    // Modal Events
    document.querySelectorAll(".modal-close-btn, .modal-cancel-btn").forEach(btn => {
        btn.addEventListener("click", closeModals);
    });

    document.getElementById("btn-modal-confirm").addEventListener("click", submitGicChange);
}

/**
 * Module Resizers (Splitters) for custom layout adjustment (Requirement 3 & 4)
 */
function initSplitters() {
    // 1. Left-Right Vertical Splitter (Tree Width)
    const splitterV = document.getElementById("splitter-v");
    const colTree = document.getElementById("pve-col-tree");

    // Restore saved tree width from localStorage
    const savedTreeWidth = localStorage.getItem("pve_tree_width");
    if (savedTreeWidth && colTree) {
        colTree.style.width = `${savedTreeWidth}px`;
    }

    if (splitterV && colTree) {
        let isDraggingV = false;
        let startX, startWidth;

        splitterV.addEventListener("mousedown", (e) => {
            isDraggingV = true;
            startX = e.clientX;
            startWidth = colTree.offsetWidth;
            splitterV.classList.add("dragging");
            document.body.style.cursor = "col-resize";
            document.body.style.userSelect = "none";
        });

        document.addEventListener("mousemove", (e) => {
            if (!isDraggingV) return;
            const newWidth = Math.min(Math.max(startWidth + (e.clientX - startX), 160), 600);
            colTree.style.width = `${newWidth}px`;
        });

        document.addEventListener("mouseup", () => {
            if (isDraggingV) {
                isDraggingV = false;
                splitterV.classList.remove("dragging");
                document.body.style.cursor = "";
                document.body.style.userSelect = "";
                localStorage.setItem("pve_tree_width", colTree.offsetWidth);
            }
        });

        splitterV.addEventListener("dblclick", () => {
            if (colTree.offsetWidth === 250) {
                colTree.style.width = "180px";
            } else {
                colTree.style.width = "250px";
            }
            localStorage.setItem("pve_tree_width", colTree.offsetWidth);
        });
    }

    // 2. Top-Bottom Horizontal Splitter (Bottom Console Height)
    const splitterH = document.getElementById("splitter-h");
    const colConsole = document.getElementById("pve-bottom-console");
    const btnToggleConsole = document.getElementById("btn-toggle-console");

    // Restore saved console height from localStorage
    const savedConsoleHeight = localStorage.getItem("pve_console_height");
    if (savedConsoleHeight && colConsole) {
        colConsole.style.height = `${savedConsoleHeight}px`;
        updateConsoleToggleIcon();
    }

    if (splitterH && colConsole) {
        let isDraggingH = false;
        let startY, startHeight;

        splitterH.addEventListener("mousedown", (e) => {
            isDraggingH = true;
            startY = e.clientY;
            startHeight = colConsole.offsetHeight;
            splitterH.classList.add("dragging");
            document.body.style.cursor = "row-resize";
            document.body.style.userSelect = "none";
        });

        document.addEventListener("mousemove", (e) => {
            if (!isDraggingH) return;
            const newHeight = Math.min(Math.max(startHeight - (e.clientY - startY), 26), 500);
            colConsole.style.height = `${newHeight}px`;
            updateConsoleToggleIcon();
        });

        document.addEventListener("mouseup", () => {
            if (isDraggingH) {
                isDraggingH = false;
                splitterH.classList.remove("dragging");
                document.body.style.cursor = "";
                document.body.style.userSelect = "";
                localStorage.setItem("pve_console_height", colConsole.offsetHeight);
            }
        });

        splitterH.addEventListener("dblclick", toggleConsoleCollapse);
    }

    if (btnToggleConsole) {
        btnToggleConsole.addEventListener("click", toggleConsoleCollapse);
    }
}

function toggleConsoleCollapse() {
    const colConsole = document.getElementById("pve-bottom-console");
    if (!colConsole) return;
    if (colConsole.offsetHeight > 32) {
        colConsole.dataset.prevHeight = colConsole.offsetHeight;
        colConsole.style.height = "26px";
    } else {
        const prev = colConsole.dataset.prevHeight || 140;
        colConsole.style.height = `${prev}px`;
    }
    localStorage.setItem("pve_console_height", colConsole.offsetHeight);
    updateConsoleToggleIcon();
}

function updateConsoleToggleIcon() {
    const colConsole = document.getElementById("pve-bottom-console");
    const btn = document.getElementById("btn-toggle-console");
    if (!btn || !colConsole) return;
    if (colConsole.offsetHeight <= 32) {
        btn.innerHTML = `<i class="fa fa-chevron-up"></i>`;
        btn.title = "展开控制台";
    } else {
        btn.innerHTML = `<i class="fa fa-chevron-down"></i>`;
        btn.title = "折叠控制台";
    }
}

function initDefaultTasks() {
    const now = new Date();
    const fmt = (d) => {
        const m = (d.getMonth() + 1).toString().padStart(2, '0');
        const day = d.getDate().toString().padStart(2, '0');
        const h = d.getHours().toString().padStart(2, '0');
        const min = d.getMinutes().toString().padStart(2, '0');
        const s = d.getSeconds().toString().padStart(2, '0');
        return `${m}-${day} ${h}:${min}:${s}`;
    };

    addTaskLog("创建集群", "OK", fmt(new Date(now.getTime() - 120000)));
    addTaskLog("启动 PVE GIC 管理服务", "OK", fmt(new Date(now.getTime() - 30000)));
}

function addTaskLog(description, status = "OK", customTime = null) {
    const now = new Date();
    const fmt = (d) => {
        const m = (d.getMonth() + 1).toString().padStart(2, '0');
        const day = d.getDate().toString().padStart(2, '0');
        const h = d.getHours().toString().padStart(2, '0');
        const min = d.getMinutes().toString().padStart(2, '0');
        const s = d.getSeconds().toString().padStart(2, '0');
        return `${m}-${day} ${h}:${min}:${s}`;
    };

    const task = {
        time: customTime || fmt(now),
        node: AppState.selectedNode || Object.keys(AppState.nodes)[0] || "pve",
        user: AppState.currentUser || "root@pam",
        desc: description,
        status: status
    };

    AppState.taskLogs.unshift(task);
    if (AppState.taskLogs.length > 50) AppState.taskLogs.pop();
    renderTaskLogs();
}

function renderTaskLogs() {
    const tbody = document.getElementById("task-log-body");
    if (!tbody) return;
    tbody.innerHTML = "";

    AppState.taskLogs.forEach(t => {
        const tr = document.createElement("tr");
        const statusColor = t.status === 'OK' ? '#2ecc71' : (t.status === 'WARN' ? '#e67e22' : '#e74c3c');
        tr.innerHTML = `
            <td>${t.time}</td>
            <td>${t.node}</td>
            <td>${t.user}</td>
            <td>${t.desc}</td>
            <td style="color: ${statusColor}; font-weight: bold;">${t.status}</td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Trigger full scan on all cluster nodes (Requirement 8)
 */
async function performScan(showToast = true) {
    if (AppState.isSyncing || !AppState.currentUser) return;
    AppState.isSyncing = true;
    updateSyncToast(true, "正在自动扫描 PVE 节点及虚拟机...");

    const icon = document.getElementById("sync-icon");
    if (icon) icon.classList.add("spin-anim");

    try {
        const resp = await fetch("/api/v1/sync", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (resp.status === 401) {
            showLoginModal();
            return;
        }

        const data = await resp.json();
        if (data.success) {
            if (data.pve_version) {
                updatePveVersionLabel(data.pve_version);
            }
            AppState.nodes = data.nodes || {};
            AppState.vms = data.vms || {};
            AppState.clusterName = data.cluster_name || AppState.clusterName || "";
            AppState.localNode = data.local_node || AppState.localNode || "";
            AppState.localIp = data.local_ip || AppState.localIp || "";
            AppState.lastSyncTime = new Date();

            renderServerTree();
            renderVMTable();
            updateStats();
            HistoryManager.fetchHistory();

            addTaskLog("自动扫描集群虚拟机及 GIC 运行状态", "OK");

            if (showToast) {
                showToastMessage(`扫描成功: 发现 ${Object.keys(AppState.nodes).length} 个节点, ${Object.keys(AppState.vms).length} 台虚拟机`);
            }
        } else {
            showToastMessage("扫描返回异常: " + (data.error || "未知错误"), true);
        }
    } catch (err) {
        console.error("Scan error:", err);
        showToastMessage("无法连接 PVE 8004/8005 服务: " + err.message, true);
    } finally {
        AppState.isSyncing = false;
        if (icon) icon.classList.remove("spin-anim");
        updateSyncToast(false);
    }
}

async function fetchVMData() {
    try {
        const resp = await fetch("/api/v1/vms");
        if (resp.status === 401) {
            showLoginModal();
            return;
        }
        const data = await resp.json();
        if (data.success) {
            if (data.pve_version) {
                updatePveVersionLabel(data.pve_version);
            }
            AppState.nodes = data.nodes || {};
            AppState.vms = data.vms || {};
            AppState.clusterName = data.cluster_name || AppState.clusterName || "";
            AppState.localNode = data.local_node || AppState.localNode || "";
            AppState.localIp = data.local_ip || AppState.localIp || "";
            AppState.lastSyncTime = new Date();
            renderServerTree();
            renderVMTable();
            updateStats();
            HistoryManager.fetchHistory();
        }
    } catch (err) {
        console.warn("Heartbeat fetch failed:", err);
    }
}

/**
 * Render Left Server View Tree with PVE Official Vector Icons (Requirement 1)
 */
function renderServerTree() {
    const rootItem = document.getElementById("tree-root-item");
    if (AppState.selectedNode === null && AppState.selectedVmId === null) {
        rootItem.classList.add("active");
    } else {
        rootItem.classList.remove("active");
    }

    const rootName = AppState.clusterName ? `数据中心 (${AppState.clusterName})` : "数据中心";
    const rootStrong = rootItem.querySelector("span strong");
    if (rootStrong) rootStrong.textContent = rootName;

    const container = document.getElementById("tree-node-list");
    container.innerHTML = "";

    const nodesList = Object.values(AppState.nodes);

    nodesList.forEach(node => {
        const isNodeActive = AppState.selectedNode === node.name && !AppState.selectedVmId;

        // Node level (pve) - Official Server Icon with Green Check Online Status
        const nodeDiv = document.createElement("div");
        nodeDiv.className = `pve-tree-item tree-level-1 ${isNodeActive ? 'active' : ''}`;
        nodeDiv.innerHTML = `
            <span class="tree-expander"><i class="fa fa-caret-down"></i></span>
            ${PVEIcons.node}
            <span><strong>${node.name}</strong></span>
            <span style="color: var(--pve-text-muted); font-size: 11px; margin-left: 4px;">(${node.ip || '-'})</span>
        `;
        nodeDiv.addEventListener("click", (e) => {
            e.stopPropagation();
            navigateToNode(node.name);
        });
        container.appendChild(nodeDiv);

        // VM Children under this node - Official Green/Grey Monitor Icons
        const vmsInNode = Object.values(AppState.vms).filter(v => v.node === node.name).sort((a,b) => a.vmid - b.vmid);
        vmsInNode.forEach(vm => {
            const isVmActive = AppState.selectedVmId === vm.vmid;
            const isRunning = vm.status === "running";
            const vmItem = document.createElement("div");
            vmItem.className = `pve-tree-item tree-level-2 ${isVmActive ? 'active' : ''}`;

            const vmIcon = isRunning ? PVEIcons.vmRunning : PVEIcons.vmStopped;

            // Resolve GIC for Tree indicator tag (Requirement 1 & 3: circle tag like PVE)
            const gicVer = vm.active_gic || vm.effective_gic || (vm.vcpus <= 8 ? "2" : "3");
            const gicTag = `<span class="pve-tree-tag ${gicVer === '2' ? 'gic2-tag' : 'gic3-tag'}" title="${gicVer === '2' ? '当前配置/引导为 GICv2 中断' : '当前配置/引导为 GICv3 中断'}"></span>`;

            vmItem.innerHTML = `
                <span class="tree-leaf-spacer"></span>
                ${vmIcon}
                <span>${vm.vmid} (${escapeHtml(vm.name)})</span>
                ${gicTag}
            `;
            vmItem.addEventListener("click", (e) => {
                e.stopPropagation();
                navigateToVm(node.name, vm);
            });
            container.appendChild(vmItem);
        });
    });
}

/**
 * View Navigation Functions (Datacenter, Node, VM Scopes)
 */
window.navigateToDatacenter = function() {
    AppState.selectedNode = null;
    AppState.selectedVmId = null;
    AppState.selectedVmIds.clear();
    renderServerTree();
    renderVMTable();
    updateToolbarButtons();
    updateStats();
    const rootTitle = AppState.clusterName ? `数据中心 (${AppState.clusterName})` : "数据中心";
    updateBreadcrumb(`<span class="breadcrumb-link" onclick="navigateToDatacenter()"><i class="fa fa-database"></i> ${rootTitle}</span> &gt; <span>⚡ ARM64 虚拟机 GIC 中断控制器管理</span>`);
};

window.navigateToNode = function(nodeName) {
    const node = AppState.nodes[nodeName] || { name: nodeName };
    AppState.selectedNode = nodeName;
    AppState.selectedVmId = null;
    AppState.selectedVmIds.clear();
    renderServerTree();
    renderVMTable();
    updateToolbarButtons();
    updateStats();
    const rootTitle = AppState.clusterName ? `数据中心 (${AppState.clusterName})` : "数据中心";
    updateBreadcrumb(`<span class="breadcrumb-link" onclick="navigateToDatacenter()"><i class="fa fa-database"></i> ${rootTitle}</span> &gt; <span class="breadcrumb-link" onclick="navigateToNode('${node.name}')"><i class="fa fa-server"></i> ${node.name} (${node.ip || '-'})</span> &gt; <span>虚拟机 GIC 中断管理</span>`);
};

window.navigateToVm = function(nodeName, vm) {
    const node = AppState.nodes[nodeName] || { name: nodeName };
    AppState.selectedNode = nodeName;
    AppState.selectedVmId = vm.vmid;
    AppState.selectedVmIds.clear();
    AppState.selectedVmIds.add(vm.vmid);
    renderServerTree();
    renderVMTable();
    updateToolbarButtons();
    updateStats();
    const rootTitle = AppState.clusterName ? `数据中心 (${AppState.clusterName})` : "数据中心";
    updateBreadcrumb(`<span class="breadcrumb-link" onclick="navigateToDatacenter()"><i class="fa fa-database"></i> ${rootTitle}</span> &gt; <span class="breadcrumb-link" onclick="navigateToNode('${node.name}')"><i class="fa fa-server"></i> ${node.name}</span> &gt; <span class="breadcrumb-current"><i class="fa fa-desktop"></i> VM ${vm.vmid} (${escapeHtml(vm.name)})</span>`);
};

function updateBreadcrumb(path) {
    const el = document.getElementById("breadcrumb-path");
    if (el) el.innerHTML = path;
}

function getFilteredVMs() {
    let list = Object.values(AppState.vms);

    if (AppState.selectedNode) {
        list = list.filter(v => v.node === AppState.selectedNode);
    }
    if (AppState.selectedVmId) {
        list = list.filter(v => v.vmid === AppState.selectedVmId);
    }

    if (AppState.searchQuery) {
        const q = AppState.searchQuery;
        list = list.filter(v => {
            return (
                String(v.vmid).includes(q) ||
                (v.name && v.name.toLowerCase().includes(q)) ||
                (v.node && v.node.toLowerCase().includes(q)) ||
                (v.primary_ip && v.primary_ip.includes(q)) ||
                (v.active_gic && v.active_gic.toLowerCase().includes(q)) ||
                (v.effective_gic && v.effective_gic.toLowerCase().includes(q)) ||
                (v.config_gic && v.config_gic.toLowerCase().includes(q))
            );
        });
    }

    return list.sort((a, b) => a.vmid - b.vmid);
}

/**
 * Render VM Data Grid (Requirement 1, 2, 3)
 * Requirement 2: Identical length for GICv2 and GICv3 badges (76px fixed width)
 * Requirement 3: Stopped VMs also marked with Red/Green GIC tags
 */
function renderVMTable() {
    const tbody = document.getElementById("vm-table-body");
    tbody.innerHTML = "";

    const vms = getFilteredVMs();

    if (vms.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--pve-text-muted); padding: 24px;">未匹配到符合条件的虚拟机</td></tr>`;
        return;
    }

    vms.forEach(vm => {
        const tr = document.createElement("tr");
        const isSelected = AppState.selectedVmIds.has(vm.vmid);
        if (isSelected) tr.classList.add("selected");

        const nodeInfo = AppState.nodes[vm.node] || {};
        const nodeIp = nodeInfo.ip || "-";

        // Status
        const isRunning = vm.status === "running";
        const statusHtml = isRunning
            ? `<span class="status-indicator running"></span><span style="color:#2ecc71; font-weight:500;">运行中</span>`
            : `<span class="status-indicator stopped"></span><span style="color:var(--pve-text-muted);">已关机</span>`;

        // VM IP
        let vmIpHtml = `<span style="font-family: monospace; font-weight:500;">${vm.primary_ip || '-'}</span>`;
        if (vm.ips && vm.ips.length > 1) {
            vmIpHtml += ` <span title="${vm.ips.join(', ')}" style="cursor: help; color: var(--pve-active-blue); font-size:11px;">(+${vm.ips.length - 1})</span>`;
        }

        // Determine GIC Version for both Running & Stopped (Requirement 2 & Requirement 3)
        // If running, prioritize QMP active_gic; if stopped, use config or architectural default (<=8: GICv2, >=9: GICv3)
        let resolvedGic = vm.active_gic || vm.effective_gic;
        if (!resolvedGic || resolvedGic === "default") {
            resolvedGic = vm.vcpus <= 8 ? "2" : "3";
        }

        let gicBadgeHtml = "";
        if (resolvedGic === "2") {
            // Requirement 1 & 2: GICv2 Red, strictly equal fixed width 76px
            const titleMsg = isRunning
                ? "运行中: GICv2 中断控制器！在 ARM64 宿主且核数<=8时容易卡在固件Logo，建议切换为GICv3"
                : "已关机: 配置/默认 GICv2 中断控制器（核数<=8，建议切换为GICv3）";
            gicBadgeHtml = `<span class="pve-tag tag-gicv2" title="${titleMsg}">GICv2</span>`;
        } else {
            // Requirement 1 & 2: GICv3 Green, strictly equal fixed width 76px
            const titleMsg = isRunning
                ? "运行中: GICv3 中断控制器，引导和多核性能良好"
                : "已关机: 配置/默认 GICv3 中断控制器（正常引导配置）";
            gicBadgeHtml = `<span class="pve-tag tag-gicv3" title="${titleMsg}">GICv3</span>`;
        }

        // Pending restart tag
        let pendingHtml = "";
        if (vm.pending_restart) {
            pendingHtml = `<span class="tag-pending" title="配置已更新，需关机重启生效">需重启</span>`;
        }

        // Config GIC
        let cfgText = vm.config_gic || "系统默认";
        if (cfgText === "3") cfgText = "GICv3 (已配置)";
        else if (cfgText === "2") cfgText = "GICv2 (已配置)";
        else if (cfgText === "host") cfgText = "host (宿主)";
        else if (cfgText === "max") cfgText = "max (最高)";
        else if (cfgText === "default") cfgText = "系统默认(继承)";

        // Action Buttons (Requirement 1 & 2: Start, Shutdown, Stop, Reboot)
        let actionButtonsHtml = "";
        if (isRunning) {
            actionButtonsHtml = `
                <button class="pve-btn pve-btn-power" onclick="promptPowerAction(${vm.vmid}, '${vm.node}', 'shutdown', '${escapeHtml(vm.name)}')" title="正常关机 (发送 ACPI 信号)">
                    <i class="fa fa-power-off" style="color: #e74c3c;"></i> 关机
                </button>
                <button class="pve-btn pve-btn-power pve-btn-power-stop" onclick="promptPowerAction(${vm.vmid}, '${vm.node}', 'stop', '${escapeHtml(vm.name)}')" title="强制停止 (立即切断电源，解决未装系统/卡死问题)">
                    <i class="fa fa-stop" style="color: #e67e22;"></i> 停止
                </button>
                <button class="pve-btn pve-btn-power" onclick="promptPowerAction(${vm.vmid}, '${vm.node}', 'reboot', '${escapeHtml(vm.name)}')" title="重启 VM ${vm.vmid}">
                    <i class="fa fa-refresh" style="color: #3498db;"></i> 重启
                </button>
                <button class="pve-btn pve-btn-power" onclick="openSingleModal(${vm.vmid}, '${vm.node}', '${vm.config_gic}')" title="配置 GIC 中断版本">
                    <i class="fa fa-cog"></i> 配置
                </button>
            `;
        } else {
            actionButtonsHtml = `
                <button class="pve-btn pve-btn-power" onclick="executePowerAction(${vm.vmid}, '${vm.node}', 'start')" title="开机启动 VM ${vm.vmid}">
                    <i class="fa fa-play" style="color: #2ecc71;"></i> 开机
                </button>
                <button class="pve-btn pve-btn-power" onclick="openSingleModal(${vm.vmid}, '${vm.node}', '${vm.config_gic}')" title="配置 GIC 中断版本">
                    <i class="fa fa-cog"></i> 配置
                </button>
            `;
        }

        tr.innerHTML = `
            <td style="text-align: center;"><input type="checkbox" class="grid-checkbox" data-vmid="${vm.vmid}" ${isSelected ? 'checked' : ''}></td>
            <td><strong>${vm.node}</strong> <span style="color:var(--pve-text-muted); font-size:11px;">(${nodeIp})</span></td>
            <td><strong>${vm.vmid}</strong></td>
            <td>${escapeHtml(vm.name)}</td>
            <td>${statusHtml}</td>
            <td>${vmIpHtml}</td>
            <td>${vm.arch} / ${vm.vcpus} 核</td>
            <td>${cfgText}</td>
            <td>${gicBadgeHtml} ${pendingHtml}</td>
            <td style="text-align: center; white-space: nowrap;">
                ${actionButtonsHtml}
            </td>
        `;

        const cb = tr.querySelector(".grid-checkbox");
        cb.addEventListener("change", (e) => {
            const id = parseInt(e.target.dataset.vmid);
            if (e.target.checked) {
                AppState.selectedVmIds.add(id);
            } else {
                AppState.selectedVmIds.delete(id);
            }
            renderVMTable();
            updateToolbarButtons();
        });

        tbody.appendChild(tr);
    });

    updateToolbarButtons();
}

function updateToolbarButtons() {
    const count = AppState.selectedVmIds.size;
    const btnGic3 = document.getElementById("btn-batch-gic3");
    const btnGic2 = document.getElementById("btn-batch-gic2");
    const btnCustom = document.getElementById("btn-batch-custom");

    const btnPowerStart = document.getElementById("btn-batch-power-start");
    const btnPowerShutdown = document.getElementById("btn-batch-power-shutdown");
    const btnPowerStop = document.getElementById("btn-batch-power-stop");
    const btnPowerReboot = document.getElementById("btn-batch-power-reboot");

    const selectedList = Array.from(AppState.selectedVmIds).map(id => AppState.vms[id]).filter(Boolean);
    const stoppedCount = selectedList.filter(v => v.status === "stopped").length;
    const runningCount = selectedList.filter(v => v.status === "running").length;

    if (btnPowerStart) {
        if (stoppedCount > 0) {
            btnPowerStart.disabled = false;
            btnPowerStart.innerHTML = `<i class="fa fa-play" style="color: #2ecc71;"></i> 批量开机 (${stoppedCount})`;
        } else {
            btnPowerStart.disabled = true;
            btnPowerStart.innerHTML = `<i class="fa fa-play" style="color: #2ecc71;"></i> 批量开机`;
        }
    }

    if (btnPowerShutdown) {
        if (runningCount > 0) {
            btnPowerShutdown.disabled = false;
            btnPowerShutdown.innerHTML = `<i class="fa fa-power-off" style="color: #e74c3c;"></i> 批量关机 (${runningCount})`;
        } else {
            btnPowerShutdown.disabled = true;
            btnPowerShutdown.innerHTML = `<i class="fa fa-power-off" style="color: #e74c3c;"></i> 批量关机`;
        }
    }

    if (btnPowerStop) {
        if (runningCount > 0) {
            btnPowerStop.disabled = false;
            btnPowerStop.innerHTML = `<i class="fa fa-stop" style="color: #e67e22;"></i> 批量停止 (${runningCount})`;
        } else {
            btnPowerStop.disabled = true;
            btnPowerStop.innerHTML = `<i class="fa fa-stop" style="color: #e67e22;"></i> 批量停止`;
        }
    }

    if (btnPowerReboot) {
        if (runningCount > 0) {
            btnPowerReboot.disabled = false;
            btnPowerReboot.innerHTML = `<i class="fa fa-refresh" style="color: #3498db;"></i> 批量重启 (${runningCount})`;
        } else {
            btnPowerReboot.disabled = true;
            btnPowerReboot.innerHTML = `<i class="fa fa-refresh" style="color: #3498db;"></i> 批量重启`;
        }
    }

    const textGic3 = btnGic3 ? btnGic3.querySelector(".btn-text") : null;
    const textGic2 = btnGic2 ? btnGic2.querySelector(".btn-text") : null;

    if (count > 0) {
        if (btnGic3) btnGic3.disabled = false;
        if (btnGic2) btnGic2.disabled = false;
        if (btnCustom) btnCustom.disabled = false;
        if (textGic3) textGic3.textContent = `批量设为 GICv3 (${count})`;
        if (textGic2) textGic2.textContent = `批量设为 GICv2 (${count})`;
    } else {
        if (btnGic3) btnGic3.disabled = true;
        if (btnGic2) btnGic2.disabled = true;
        if (btnCustom) btnCustom.disabled = true;
        if (textGic3) textGic3.textContent = `批量设为 GICv3`;
        if (textGic2) textGic2.textContent = `批量设为 GICv2`;
    }
}

function updateStats() {
    const infoHeader = document.querySelector(".pve-info-header");
    const isVmScope = AppState.selectedVmId !== null;

    // Requirement 1, 2, 3: 只有视图在数据中心和节点时才显示概览统计，虚拟机视图下隐藏
    if (isVmScope) {
        if (infoHeader) infoHeader.style.display = "none";
        return;
    }

    if (infoHeader) infoHeader.style.display = "block";

    let list = Object.values(AppState.vms);
    const viewScopeLabel = document.getElementById("view-scope-label");

    if (AppState.selectedNode) {
        // 节点视图：数量随对应的视图变化，只统计当前选定节点下的虚拟机
        list = list.filter(v => v.node === AppState.selectedNode);
        if (viewScopeLabel) {
            viewScopeLabel.textContent = `节点: ${AppState.selectedNode}`;
        }
    } else {
        // 数据中心视图：统计全集群节点下的虚拟机
        if (viewScopeLabel) {
            const rootTitle = AppState.clusterName ? `数据中心 (${AppState.clusterName})` : "全集群节点";
            viewScopeLabel.textContent = rootTitle;
        }
    }

    const total = list.length;
    let gicv3Running = 0;
    let gicv2Running = 0;
    let stopped = 0;

    list.forEach(v => {
        if (v.status === "stopped") {
            stopped++;
        } else {
            // 运行中的虚拟机 GIC 数量
            const ver = v.active_gic || v.effective_gic || (v.vcpus <= 8 ? "2" : "3");
            if (ver === "3") {
                gicv3Running++;
            } else if (ver === "2") {
                gicv2Running++;
            }
        }
    });

    const elTotal = document.getElementById("stat-total");
    const elGicv3 = document.getElementById("stat-gicv3");
    const elGicv2 = document.getElementById("stat-gicv2");
    const elStopped = document.getElementById("stat-stopped");

    if (elTotal) elTotal.textContent = total;
    if (elGicv3) elGicv3.textContent = gicv3Running;
    if (elGicv2) elGicv2.textContent = gicv2Running;
    if (elStopped) elStopped.textContent = stopped;

    if (AppState.lastSyncTime) {
        const timeEl = document.getElementById("last-sync-time-label");
        if (timeEl) timeEl.textContent = `上次扫描: ${AppState.lastSyncTime.toLocaleTimeString()}`;
    }
}

function updateSyncToast(show, msg = "") {
    const bar = document.getElementById("sync-toast-bar");
    const txt = document.getElementById("sync-toast-text");
    if (show) {
        bar.style.display = "flex";
        txt.textContent = msg;
    } else {
        setTimeout(() => {
            if (!AppState.isSyncing) bar.style.display = "none";
        }, 1200);
    }
}

function showToastMessage(msg, isError = false) {
    const bar = document.getElementById("sync-toast-bar");
    const txt = document.getElementById("sync-toast-text");
    bar.style.display = "flex";
    bar.style.backgroundColor = isError ? "#bd2130" : "#1e7e34";
    bar.style.color = "#ffffff";
    txt.textContent = msg;

    setTimeout(() => {
        bar.style.display = "none";
        bar.style.backgroundColor = "#007acc";
    }, 3500);
}

// Modal handling
let modalContext = { isBatch: false, vmids: [], node: null };

window.openSingleModal = function(vmid, node, curGic) {
    modalContext = { isBatch: false, vmids: [vmid], node: node };
    document.getElementById("modal-title").textContent = `虚拟机 VM ${vmid} 中断控制器配置 (GIC)`;
    document.getElementById("modal-desc").textContent = `所属节点：${node}`;
    document.getElementById("modal-gic-select").value = curGic || "default";
    document.getElementById("gic-modal").style.display = "flex";
};

function openBatchModal(targetGic) {
    if (AppState.selectedVmIds.size === 0) return;
    const ids = Array.from(AppState.selectedVmIds);
    modalContext = { isBatch: true, vmids: ids, node: null };
    document.getElementById("modal-title").textContent = `批量配置虚拟机中断控制器 (${ids.length} 台)`;
    document.getElementById("modal-desc").textContent = `将对以下虚拟机生效: VM ${ids.join(', ')}`;
    document.getElementById("modal-gic-select").value = targetGic;
    document.getElementById("gic-modal").style.display = "flex";
}

function closeModals() {
    document.getElementById("gic-modal").style.display = "none";
}

async function submitGicChange() {
    const target = document.getElementById("modal-gic-select").value;
    closeModals();

    const targetDesc = target === "host" ? "系统默认(继承)" : `GICv${target}`;
    showToastMessage("正在提交配置修改请求...");

    try {
        if (modalContext.isBatch) {
            const payload = {
                gic_version: target,
                vms: modalContext.vmids.map(id => {
                    const vm = AppState.vms[id];
                    return { vmid: id, node: vm ? vm.node : null };
                })
            };

            const gicMsgId = MessageCenter.add({
                user: AppState.currentUser || "root@pam",
                source_node: AppState.localNode || window.location.hostname,
                target_node: "集群多节点",
                action: "batch_gic",
                action_name: "批量GIC",
                status: "in_progress",
                title: `批量设置 ${modalContext.vmids.length} 台虚拟机为 ${targetDesc}`,
                detail: `正在批量更新 ${modalContext.vmids.map(id => 'VM ' + id).join(', ')} 的中断控制器为 ${targetDesc}...`
            });

            const resp = await fetch("/api/v1/vms/batch-gic", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const res = await resp.json();
            if (res.success) {
                showToastMessage(`批量修改完成！已配置 ${res.batch_count} 台虚拟机为 GIC ${target}（需重启生效）`);
                addTaskLog(`批量设置 ${res.batch_count} 台虚拟机 GIC 为 ${target}`, "OK");
                MessageCenter.update(gicMsgId, {
                    status: "success",
                    detail: `已成功将 ${res.batch_count} 台虚拟机配置为 ${targetDesc}（需完全冷关机后再开机生效）`
                });
                AppState.selectedVmIds.clear();
                performScan(false);
            } else {
                showToastMessage("批量修改失败: " + (res.error || "未知"), true);
                addTaskLog(`批量设置 GIC 失败`, "ERROR");
                MessageCenter.update(gicMsgId, {
                    status: "error",
                    is_exception: true,
                    detail: `批量修改 GIC 失败: ` + (res.error || "未知")
                });
            }
        } else {
            const vmid = modalContext.vmids[0];
            const node = modalContext.node;
            const vm = AppState.vms[vmid] || {};

            const gicMsgId = MessageCenter.add({
                vmid: vmid,
                vm_name: vm.name || `VM ${vmid}`,
                user: AppState.currentUser || "root@pam",
                source_node: AppState.localNode || window.location.hostname,
                target_node: node,
                action: "gic",
                action_name: "配置GIC",
                status: "in_progress",
                title: `VM ${vmid} 设置为 ${targetDesc}`,
                detail: `正在将 VM ${vmid} (${node}) 中断控制器更新为 ${targetDesc}...`
            });

            const resp = await fetch(`/api/v1/vms/${vmid}/gic`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ gic_version: target, node: node })
            });
            const res = await resp.json();
            if (res.success) {
                showToastMessage(`VM ${vmid} 配置已更新为 GIC ${target}（需完全关机后开机生效）`);
                addTaskLog(`VM ${vmid} - GIC 配置更新为 ${target}`, "OK");
                MessageCenter.update(gicMsgId, {
                    status: "success",
                    detail: `VM ${vmid} 中断控制器已成功更新为 ${targetDesc}（需完全冷关机后再开机生效）`
                });
                performScan(false);
            } else {
                showToastMessage(`VM ${vmid} 配置失败: ` + (res.error || "未知"), true);
                addTaskLog(`VM ${vmid} - GIC 配置更新失败`, "ERROR");
                MessageCenter.update(gicMsgId, {
                    status: "error",
                    is_exception: true,
                    detail: `VM ${vmid} 配置失败: ` + (res.error || "未知")
                });
            }
        }
    } catch (e) {
        showToastMessage("请求失败: " + e.message, true);
    }
}

// ============================================================================
// Power Management Operations (Requirement 4: Start, Shutdown, Reboot)
// ============================================================================
let powerModalContext = { action: null, isBatch: false, vmid: null, node: null, name: "", targets: [] };

window.promptPowerAction = function(vmid, node, action, name) {
    powerModalContext = { action, isBatch: false, vmid, node, name, targets: [] };
    const modal = document.getElementById("power-confirm-modal");
    const titleEl = document.getElementById("power-modal-title");
    const msgEl = document.getElementById("power-modal-message");
    const subEl = document.getElementById("power-modal-sub");
    const iconEl = document.getElementById("power-modal-icon");

    const vm = AppState.vms[vmid] || {};
    const isGic2 = (vm.active_gic === "2" || vm.effective_gic === "2" || vm.config_gic === "2");

    let actionName = action === "shutdown" ? "关机" : (action === "stop" ? "强制停止" : (action === "reboot" ? "重启" : "开机"));
    titleEl.innerHTML = `<i class="fa fa-power-off"></i> 确认虚拟机${actionName}`;
    msgEl.textContent = `确定要对虚拟机 ${vmid} (${name || 'VM ' + vmid}) 执行【${actionName}】操作吗？`;

    if (action === "shutdown") {
        iconEl.innerHTML = `<i class="fa fa-power-off" style="color: #e74c3c;"></i>`;
        if (isGic2) {
            subEl.innerHTML = `
                <div style="background: rgba(230, 126, 34, 0.12); border-left: 3px solid #e67e22; padding: 8px 10px; margin-top: 6px; border-radius: 2px;">
                    <strong style="color: #e67e22;"><i class="fa fa-bolt"></i> 特别提示 (当前运行于 GICv2 中断)：</strong><br>
                    在 ARM64 宿主环境下，GICv2 中断极易导致虚拟机开机时<strong>卡在固件 Logo 界面</strong>。若开机时曾卡在 Logo 说明操作系统内核尚未引导，按【关机】键发送 ACPI 信号将<strong>无法响应</strong>。<br>
                    <strong>解决办法：</strong>若当前卡在 Logo，请直接点击<strong>【强制停止】</strong>按钮断电关机，随后将 GIC 切换为 <strong>GICv3</strong> 即可彻底解决卡死。
                </div>
            `;
        } else {
            subEl.innerHTML = `
                <div style="background: rgba(46, 204, 113, 0.12); border-left: 3px solid #2ecc71; padding: 8px 10px; margin-top: 6px; border-radius: 2px;">
                    <strong style="color: #27ae60;"><i class="fa fa-info-circle"></i> 提示：</strong><br>
                    正常关机将向虚拟机发送 ACPI 软关机信号（已安装操作系统的虚拟机会安全同步磁盘并退出服务，通常需 10~35 秒）。<br>
                    <span style="color: var(--pve-text-muted);">注：若该机器尚未安装操作系统或处于安装向导界面，将无法响应 ACPI 软关机，请使用【强制停止】功能直接切断电源。</span>
                </div>
            `;
        }
    } else if (action === "stop") {
        iconEl.innerHTML = `<i class="fa fa-stop" style="color: #e67e22;"></i>`;
        subEl.innerHTML = `
            <div style="color: var(--pve-text-normal); margin-top: 6px; line-height: 1.4;">
                ⚠️ <strong>警告：</strong>强制停止将立即切断虚拟机电源（如同拔掉物理电源）。<br>
                此功能专门用于解决<strong>开机卡在固件 Logo</strong>、<strong>未安装系统无 ACPI 响应</strong>或<strong>系统完全卡死</strong>等无法正常关机的情况。
            </div>
        `;
    } else if (action === "reboot") {
        iconEl.innerHTML = `<i class="fa fa-refresh" style="color: #3498db;"></i>`;
        subEl.textContent = "提示：系统重启为热重启。注意：QEMU GIC 中断控制器硬件变更需要完全冷关机再开机生效。";
    } else {
        iconEl.innerHTML = `<i class="fa fa-play" style="color: #2ecc71;"></i>`;
        subEl.textContent = "提示：将启动虚拟机并应用最新的 GIC 中断控制器配置。";
    }

    modal.style.display = "flex";
};

let suggestStopContext = null;
const activeShutdownWatchdogs = new Map();

function startShutdownWatchdog(vmid, node, targetGic, msgId = null) {
    if (activeShutdownWatchdogs.has(vmid)) {
        clearInterval(activeShutdownWatchdogs.get(vmid));
    }

    let elapsed = 0;
    const interval = 2500;
    const timeout = 12500; // 12.5s maximum wait for ACPI shutdown

    const timerId = setInterval(async () => {
        elapsed += interval;
        try {
            await performScan(false);
        } catch (e) {}

        const vm = AppState.vms[vmid];
        
        // If VM is now stopped, safe shutdown succeeded!
        if (vm && vm.status === "stopped") {
            clearInterval(timerId);
            activeShutdownWatchdogs.delete(vmid);
            showToastMessage(`VM ${vmid} 已安全平稳关机！`);
            addTaskLog(`VM ${vmid} - 正常安全关机完成 (VM 已停止运行)`, "OK");
            if (msgId) {
                MessageCenter.update(msgId, {
                    status: "success",
                    detail: `VM ${vmid} 正常关机完成，系统服务已平稳终止并断电退出。`
                });
            }
            return;
        }

        // If timeout reached and VM is STILL running: ACPI failed to shut down the machine!
        // Requirement 1, 2 & 4: MUST pop up the modal, record in message center, and provide 1-click stop!
        if (elapsed >= timeout) {
            clearInterval(timerId);
            activeShutdownWatchdogs.delete(vmid);
            
            const isGic2 = (targetGic === "2" || (vm && (vm.active_gic === "2" || vm.effective_gic === "2" || vm.config_gic === "2")));
            const reason = isGic2 ? "GICv2固件卡Logo死锁未响应" : "未安装操作系统无ACPI响应";
            
            if (msgId) {
                MessageCenter.update(msgId, {
                    status: "warning",
                    is_exception: true,
                    can_force_stop: true,
                    detail: isGic2
                        ? `关机未响应 (GICv2 固件卡 Logo)：该虚拟机使用 GICv2 运行，开机可能死锁卡在 UEFI 界面，无法响应 ACPI 关机指令，建议立即执行强制停止。`
                        : `关机未响应 (未安装操作系统)：该虚拟机未安装操作系统或处于系统安装引导界面，无 ACPI 软关机服务，建议立即执行强制停止。`
                });
            }

            openSuggestStopModal(vmid, node, reason, isGic2 ? "2" : "3");
            addTaskLog(`VM ${vmid} - 关机未响应 (${isGic2 ? 'GICv2卡Logo' : '未装系统无ACPI'}，已弹窗引导强制停止)`, "WARN");
        }
    }, interval);

    activeShutdownWatchdogs.set(vmid, timerId);
}

function openSuggestStopModal(vmid, node, errMsg, vmGic) {
    suggestStopContext = { vmid, node };
    const modal = document.getElementById("suggest-stop-modal");
    const titleEl = document.getElementById("suggest-stop-title");
    const headerBar = modal ? modal.querySelector(".modal-header-bar") : null;
    const msgEl = document.getElementById("suggest-stop-message");
    const reasonEl = document.getElementById("suggest-stop-reason");

    const vm = AppState.vms[vmid] || {};
    const isGic2 = vmGic === "2" || vm.active_gic === "2" || vm.effective_gic === "2" || (errMsg && errMsg.includes("GICv2"));

    if (msgEl) msgEl.textContent = `虚拟机 VM ${vmid} (节点: ${node}) 正常关机未响应`;

    if (isGic2) {
        if (titleEl) titleEl.innerHTML = `<i class="fa fa-bolt"></i> 虚拟机正常关机未响应 (GICv2 固件卡Logo)`;
        if (headerBar) headerBar.style.backgroundColor = "#d35400";
        if (reasonEl) {
            reasonEl.style.borderLeftColor = "#e67e22";
            reasonEl.innerHTML = `
                <strong style="color: #e67e22;">根因分析 (GICv2 固件卡 Logo)：</strong><br>
                检测到该虚拟机当前使用 <strong>GICv2</strong> 中断控制器运行。<br>
                在 ARM64 宿主环境下，GICv2 存在严重固件死锁缺陷，开机极易死锁并卡在 <strong>Tianocore / Proxmox 开机 Logo 界面</strong>，导致操作系统内核未能加载，因而无法接收并处理 ACPI 关机信号。<br>
                <div style="margin-top: 6px; font-weight: bold; color: var(--pve-text-light);">
                    解决建议：请点击下方【立即强制停止】切电关机，随后在配置中切换为【GICv3】彻底解决卡 Logo 缺陷。
                </div>
            `;
        }
    } else {
        if (titleEl) titleEl.innerHTML = `<i class="fa fa-exclamation-triangle"></i> 虚拟机正常关机未响应 (未安装系统)`;
        if (headerBar) headerBar.style.backgroundColor = "#bd2130";
        if (reasonEl) {
            reasonEl.style.borderLeftColor = "#bd2130";
            reasonEl.innerHTML = `
                <strong style="color: #e74c3c;">根因分析 (未安装操作系统)：</strong><br>
                该虚拟机尚未安装操作系统（或处于系统安装引导向导/BIOS菜单界面），未运行 ACPI 电源服务，因而无法响应软关机信号。<br>
                <div style="margin-top: 6px; font-weight: bold; color: var(--pve-text-light);">
                    解决建议：请点击下方【立即强制停止】直接切断电源关机。
                </div>
            `;
        }
    }

    if (modal) modal.style.display = "flex";
}

function closeSuggestStopModal() {
    const modal = document.getElementById("suggest-stop-modal");
    if (modal) modal.style.display = "none";
}

window.executePowerAction = async function(vmid, node, action) {
    let actionName = action === "shutdown" ? "关机" : (action === "reboot" ? "重启" : (action === "stop" ? "强制停止" : "开机"));
    
    // If stop action is invoked, cancel any active shutdown watchdog for this VM
    if (action === "stop" && activeShutdownWatchdogs.has(vmid)) {
        clearInterval(activeShutdownWatchdogs.get(vmid));
        activeShutdownWatchdogs.delete(vmid);
    }

    const vmObj = AppState.vms[vmid] || {};
    const vmName = vmObj.name || `VM ${vmid}`;

    // Record action in Message Center (Requirement 2)
    const msgId = MessageCenter.add({
        vmid: vmid,
        vm_name: vmName,
        user: AppState.currentUser || "root@pam",
        source_node: AppState.localNode || window.location.hostname,
        target_node: node,
        node: node,
        action: action,
        action_name: actionName,
        status: "in_progress",
        title: `${vmName} 执行${actionName}`,
        detail: action === "shutdown"
            ? `已下发 ACPI 软关机信号，正在监测系统退出状态 (最长 12.5 秒)...`
            : `正在执行${actionName}指令...`
    });

    showToastMessage(`正在向 VM ${vmid} (${node}) 发送${actionName}指令...`);

    try {
        const resp = await fetch(`/api/v1/vms/${vmid}/power`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: action, node: node })
        });
        const res = await resp.json();
        if (res.success) {
            if (action === "shutdown") {
                showToastMessage(`VM ${vmid} 关机指令已下发，正在监测关机状态 (最长等待 12 秒)...`);
                addTaskLog(`VM ${vmid} - 关机指令已下发，正在等待虚拟机退出...`, "OK");
                setTimeout(() => performScan(false), 800);
                startShutdownWatchdog(vmid, node, res.vm_gic, msgId);
            } else {
                showToastMessage(res.message || `VM ${vmid} ${actionName}操作成功分发！`);
                addTaskLog(`VM ${vmid} - 执行${actionName}成功: ${res.message || '指令已下发'}`, "OK");
                MessageCenter.update(msgId, {
                    status: "success",
                    detail: res.message || `${actionName}操作成功完成`
                });
                setTimeout(() => performScan(false), 1200);
            }
        } else {
            // Detect shutdown error and differentiate GICv2 Logo hang vs uninstalled OS
            const isGic2 = (res.vm_gic === "2" || vmObj.active_gic === "2" || vmObj.effective_gic === "2" || vmObj.config_gic === "2");
            if (res.suggest_stop || (res.error && (res.error.includes("未安装操作系统") || res.error.includes("ACPI") || res.error.includes("GICv2")))) {
                MessageCenter.update(msgId, {
                    status: "warning",
                    is_exception: true,
                    can_force_stop: true,
                    detail: isGic2
                        ? `关机未响应 (GICv2 固件卡 Logo)：该虚拟机使用 GICv2 运行，开机可能死锁卡在 UEFI 界面，建议立即强制停止断电关机。`
                        : `关机未响应 (未安装操作系统)：虚拟机无 ACPI 软关机服务，建议立即强制停止断电关机。`
                });
                openSuggestStopModal(vmid, node, res.error, isGic2 ? "2" : "3");
                addTaskLog(`VM ${vmid} - 关机未响应 (${isGic2 ? 'GICv2卡Logo' : '未装系统无ACPI'}，建议强制停止)`, "WARN");
            } else {
                MessageCenter.update(msgId, {
                    status: "error",
                    is_exception: true,
                    detail: res.error || `${actionName}操作执行失败`
                });
                showToastMessage(`VM ${vmid} ${actionName}失败: ` + (res.error || "未知错误"), true);
                addTaskLog(`VM ${vmid} - 执行${actionName}失败: ${res.error || ''}`, "ERROR");
            }
        }
    } catch (e) {
        MessageCenter.update(msgId, {
            status: "error",
            is_exception: true,
            detail: "网络异常或请求超时: " + e.message
        });
        showToastMessage("请求失败: " + e.message, true);
    }
};

function promptBatchPowerAction(action) {
    const selectedList = Array.from(AppState.selectedVmIds).map(id => AppState.vms[id]).filter(Boolean);
    const targets = action === "start"
        ? selectedList.filter(v => v.status === "stopped")
        : selectedList.filter(v => v.status === "running");

    if (targets.length === 0) return;

    powerModalContext = { action, isBatch: true, targets };
    const modal = document.getElementById("power-confirm-modal");
    const titleEl = document.getElementById("power-modal-title");
    const msgEl = document.getElementById("power-modal-message");
    const subEl = document.getElementById("power-modal-sub");
    const iconEl = document.getElementById("power-modal-icon");

    let actionName = action === "shutdown" ? "关机" : (action === "stop" ? "强制停止" : (action === "reboot" ? "重启" : "开机"));
    titleEl.innerHTML = `<i class="fa fa-power-off"></i> 批量虚拟机${actionName}`;
    msgEl.textContent = `确定要对选中的 ${targets.length} 台虚拟机批量执行【${actionName}】操作吗？`;
    subEl.textContent = `涉及虚拟机: ${targets.map(t => 'VM ' + t.vmid).join(', ')}`;

    if (action === "shutdown") {
        iconEl.innerHTML = `<i class="fa fa-power-off" style="color: #e74c3c;"></i>`;
    } else if (action === "stop") {
        iconEl.innerHTML = `<i class="fa fa-stop" style="color: #e67e22;"></i>`;
        subEl.textContent += "（提示：将立即切断电源强制停止）";
    } else if (action === "reboot") {
        iconEl.innerHTML = `<i class="fa fa-refresh" style="color: #3498db;"></i>`;
    } else {
        iconEl.innerHTML = `<i class="fa fa-play" style="color: #2ecc71;"></i>`;
    }

    modal.style.display = "flex";
}

async function submitBatchPowerAction() {
    closePowerModal();
    const action = powerModalContext.action;
    const targets = powerModalContext.targets || [];
    let actionName = action === "shutdown" ? "关机" : (action === "stop" ? "强制停止" : (action === "reboot" ? "重启" : "开机"));

    showToastMessage(`正在批量执行 ${targets.length} 台虚拟机${actionName}...`);

    // Register each target into Message Center
    const msgMap = {};
    targets.forEach(t => {
        msgMap[t.vmid] = MessageCenter.add({
            vmid: t.vmid,
            vm_name: t.name || `VM ${t.vmid}`,
            user: AppState.currentUser || "root@pam",
            source_node: AppState.localNode || window.location.hostname,
            target_node: t.node,
            node: t.node,
            action: action,
            action_name: actionName,
            status: "in_progress",
            title: `批量${actionName}: VM ${t.vmid}`,
            detail: action === "shutdown"
                ? `批量下发 ACPI 软关机信号，正在监测系统退出状态...`
                : `正在批量执行${actionName}...`
        });
    });

    try {
        const resp = await fetch("/api/v1/vms/batch-power", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action: action,
                vms: targets.map(t => ({ vmid: t.vmid, node: t.node }))
            })
        });
        const res = await resp.json();
        if (res.success) {
            showToastMessage(`批量${actionName}指令已下发 (${res.batch_count} 台)`);
            addTaskLog(`批量执行 ${res.batch_count} 台虚拟机${actionName}`, "OK");
            setTimeout(() => performScan(false), 1000);
            if (action === "shutdown") {
                targets.forEach(t => startShutdownWatchdog(t.vmid, t.node, t.active_gic, msgMap[t.vmid]));
            } else {
                targets.forEach(t => {
                    MessageCenter.update(msgMap[t.vmid], {
                        status: "success",
                        detail: `VM ${t.vmid} 批量${actionName}操作成功完成`
                    });
                });
            }
        } else {
            showToastMessage(`批量${actionName}失败: ` + (res.error || "未知错误"), true);
            addTaskLog(`批量执行${actionName}失败`, "ERROR");
            targets.forEach(t => {
                MessageCenter.update(msgMap[t.vmid], {
                    status: "error",
                    is_exception: true,
                    detail: `批量${actionName}失败: ` + (res.error || "未知错误")
                });
            });
        }
    } catch (e) {
        showToastMessage("批量请求失败: " + e.message, true);
        targets.forEach(t => {
            MessageCenter.update(msgMap[t.vmid], {
                status: "error",
                is_exception: true,
                detail: "网络异常: " + e.message
            });
        });
    }
}

function closePowerModal() {
    const modal = document.getElementById("power-confirm-modal");
    if (modal) modal.style.display = "none";
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
