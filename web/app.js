/* ==========================================================================
 * WHX 哨兵 · 本机安全看板前端
 * 原生 ES6，无框架、无 import、无外部依赖；所有 API 均为同源相对路径。
 *
 * 数据接口（只读免 token，写操作带 X-Sentinel-Token）：
 *   GET  /api/status            每 2 秒
 *   GET  /api/events            每 5 秒（筛选 / 分页）
 *   GET  /api/timeline          每 30 秒（24h 趋势）
 *   GET  /api/actions/recent    每 10 秒
 *   GET  /api/token             首次写操作时获取，缓存在 sessionStorage
 *   POST /api/settings /api/allowlist /api/actions/{action}
 *   GET  /api/export            表格「导出 JSON」链接
 * ========================================================================== */
(function () {
    'use strict';

    /* ------------------------------------------------------------------ 常量 */
    var POLL_STATUS_MS = 2000;
    var POLL_EVENTS_MS = 5000;
    var POLL_TIMELINE_MS = 30000;
    var POLL_ACTIONS_MS = 10000;
    var PAGE_SIZE = 50;
    var TOKEN_KEY = 'whx.sentinel.token';
    var SEVERITIES = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];
    var SEV_LABELS = { HIGH: '高危', MEDIUM: '中危', LOW: '低危', INFO: '提示' };
    var SEV_RANK = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
    var SEV_COLORS = { HIGH: '#ff4d6d', MEDIUM: '#fb923c', LOW: '#fbbf24', INFO: '#38bdf8' };
    var STACK_ORDER = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];
    var STATUS_LABELS = { new: '未处理', ack: '已确认', ignored: '已忽略' };
    var SENSOR_STATUS_LABELS = { ok: '运行中', starting: '启动中', error: '错误', stopped: '已停止' };
    var SENSOR_STATUS_TONES = { ok: 'good', starting: 'accent', error: 'bad', stopped: 'dim' };
    var CAP_LABELS = {
        ok: '能力正常',
        degraded: '能力降级',
        needs_admin: '需要管理员',
        unavailable: '不可用',
        starting: '启动中'
    };
    var CAP_TONES = { ok: 'good', degraded: 'warn', needs_admin: 'warn', unavailable: 'bad', starting: 'accent' };
    var ALLOW_KINDS = ['process_names', 'cmdline_contains', 'paths', 'remote_ips'];
    var ALLOW_LABELS = {
        process_names: '进程名',
        cmdline_contains: '命令行标记',
        paths: '可执行路径前缀',
        remote_ips: '远端 IP'
    };
    var ACTION_LABELS = {
        scan: 'Defender 快速扫描',
        defend: 'Defender 快速扫描',
        defender_update: '更新病毒库',
        open_security_center: '打开安全中心',
        block_ip: '封锁 IP',
        unblock_ip: '解除 IP 封锁',
        kill_process: '结束进程',
        ack_event: '确认事件',
        ignore_event: '忽略事件',
        ai_analyze: 'AI 研判',
        reset_baseline: '重置基线',
        test_toast: '测试通知',
        shutdown: '停止哨兵'
    };
    var EXPOSURE_ADVICE = {
        'exposure.rdp_enabled': '如不需要远程连接，建议在「设置 → 系统 → 远程桌面」中关闭 RDP。',
        'exposure.smb1_enabled': 'SMBv1 存在已知漏洞，建议在「Windows 功能」中停用。',
        'exposure.uac_disabled': 'UAC 关闭会削弱权限隔离，建议立即重新开启。',
        'exposure.secureboot_off': '建议在 BIOS/UEFI 中开启 Secure Boot。',
        'exposure.autoplay_enabled': '建议在「设置 → 蓝牙和设备 → 自动播放」中关闭。'
    };

    /* ------------------------------------------------------------------ 工具 */
    function $(id) {
        return document.getElementById(id);
    }

    function escapeHtml(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) {
            if (ch === '&') return '&amp;';
            if (ch === '<') return '&lt;';
            if (ch === '>') return '&gt;';
            if (ch === '"') return '&quot;';
            return '&#39;';
        });
    }

    function isObject(value) {
        return !!value && typeof value === 'object' && !Array.isArray(value);
    }

    function text(value, fallback) {
        if (value === null || value === undefined || value === '') {
            return fallback === undefined ? '—' : fallback;
        }
        return String(value);
    }

    function fmtNum(value, fallback) {
        var number = Number(value);
        if (!isFinite(number)) return fallback === undefined ? '—' : fallback;
        return number.toLocaleString('zh-CN');
    }

    function fmtUptime(value) {
        var seconds = Number(value);
        if (!isFinite(seconds) || seconds < 0) return '—';
        var days = Math.floor(seconds / 86400);
        var hours = Math.floor((seconds % 86400) / 3600);
        var minutes = Math.floor((seconds % 3600) / 60);
        if (days > 0) return days + ' 天 ' + hours + ' 小时';
        if (hours > 0) return hours + ' 小时 ' + minutes + ' 分';
        if (minutes > 0) return minutes + ' 分';
        return Math.round(seconds) + ' 秒';
    }

    function fmtSeconds(value) {
        var seconds = Number(value);
        if (!isFinite(seconds) || seconds < 0) return '—';
        if (seconds >= 60 && seconds % 60 === 0) return (seconds / 60) + ' 分钟';
        if (seconds === Math.floor(seconds)) return seconds + ' 秒';
        return seconds.toFixed(1) + ' 秒';
    }

    function fmtMs(value) {
        var ms = Number(value);
        if (!isFinite(ms) || ms < 0) return '—';
        if (ms >= 1000) return (ms / 1000).toFixed(2) + ' 秒';
        return (Math.round(ms * 10) / 10) + ' ms';
    }

    function pad2(value) {
        return String(value).padStart(2, '0');
    }

    function fmtClock(value) {
        var ts = Number(value);
        if (!isFinite(ts) || ts <= 0) return '—';
        var date = new Date(ts > 1000000000000 ? ts : ts * 1000);
        return pad2(date.getHours()) + ':' + pad2(date.getMinutes()) + ':' + pad2(date.getSeconds());
    }

    function fmtDateTime(value) {
        var ts = Number(value);
        if (!isFinite(ts) || ts <= 0) return '—';
        var date = new Date(ts > 1000000000000 ? ts : ts * 1000);
        return date.getFullYear() + '-' + pad2(date.getMonth() + 1) + '-' + pad2(date.getDate()) +
            ' ' + pad2(date.getHours()) + ':' + pad2(date.getMinutes()) + ':' + pad2(date.getSeconds());
    }

    function fmtEventTime(event) {
        if (!event) return '—';
        if (event.day && event.time) {
            return String(event.day).slice(5) + ' ' + String(event.time);
        }
        if (event.time) return String(event.time);
        return fmtDateTime(event.ts || event.last_ts);
    }

    function fmtGbFromMb(value) {
        var mb = Number(value);
        if (!isFinite(mb)) return '—';
        return (mb / 1024).toFixed(1) + ' GB';
    }

    function truncate(value, max) {
        var str = String(value == null ? '' : value).replace(/\s+/g, ' ').trim();
        if (str.length <= max) return str;
        return str.slice(0, max - 1) + '…';
    }

    function normalizeSeverity(value) {
        var sev = String(value || '').toUpperCase();
        return SEVERITIES.indexOf(sev) >= 0 ? sev : 'INFO';
    }

    function normalizeStatus(value) {
        var status = String(value || '').toLowerCase();
        return status === 'ack' || status === 'ignored' ? status : 'new';
    }

    function isValidPid(value) {
        var pid = Number(value);
        return Number.isInteger(pid) && pid > 0 && pid < 4294967296;
    }

    function isValidIp(value) {
        var ip = String(value || '').trim();
        if (!ip || ip.length > 45) return false;
        if (ip.indexOf(':') >= 0) {
            return /^[0-9a-fA-F:.]+$/.test(ip);
        }
        var parts = ip.split('.');
        if (parts.length !== 4) return false;
        return parts.every(function (part) {
            return /^\d{1,3}$/.test(part) && Number(part) <= 255;
        });
    }

    function debounce(fn, wait) {
        var timer = null;
        return function () {
            var args = arguments;
            var self = this;
            clearTimeout(timer);
            timer = setTimeout(function () {
                fn.apply(self, args);
            }, wait);
        };
    }

    function storageGet(key) {
        try {
            return window.sessionStorage.getItem(key);
        } catch (error) {
            return null;
        }
    }

    function storageSet(key, value) {
        try {
            window.sessionStorage.setItem(key, value);
        } catch (error) {
            /* 隐私模式下 sessionStorage 可能不可用，退化为每次重新取 token */
        }
    }

    function storageRemove(key) {
        try {
            window.sessionStorage.removeItem(key);
        } catch (error) {
            /* ignore */
        }
    }

    function describeError(error) {
        if (!error) return '未知错误';
        var message = error.message || String(error);
        if (/Failed to fetch|NetworkError|Load failed|Network request failed/i.test(message)) {
            return '无法连接本机哨兵服务（127.0.0.1:8765）';
        }
        return message;
    }

    /* ------------------------------------------------------------------ 状态 */
    var state = {
        connected: null,
        hasStatus: false,
        status: null,
        settings: null,
        sensors: [],
        stats: null,
        events: [],
        eventsTotal: 0,
        eventsRenderedOnce: false,
        offlineRendered: false,
        offset: 0,
        filters: { severity: '', sensor: '', status: '', q: '' },
        timeline: null,
        currentEvent: null,
        eventRequestSeq: 0,
        activeDrawer: null,
        drawerTrigger: null,
        eventDrawerOpen: false,
        settingsDrawerOpen: false,
        settingsPopulated: false,
        lastStatusAt: 0,
        polling: { status: false, events: false },
        tokenPromise: null,
        chartGeom: null,
        chartHover: -1,
        flashTimes: Object.create(null),
        sensorOptionKey: ''
    };

    /* ------------------------------------------------------------------ DOM */
    var dom = {};

    function cacheDom() {
        dom.connPill = $('conn-pill');
        dom.connText = $('conn-text');
        dom.uptime = $('uptime');
        dom.adminBadge = $('admin-badge');
        dom.btnSecurityCenter = $('btn-security-center');
        dom.btnSettings = $('btn-settings');
        dom.lastRefresh = $('last-refresh');
        dom.flashStack = $('flash-stack');
        dom.overviewMeta = $('overview-meta');

        dom.statCards = Object.create(null);
        Array.prototype.forEach.call(document.querySelectorAll('[data-stat]'), function (card) {
            dom.statCards[card.getAttribute('data-stat')] = card;
        });

        dom.chartTotal = $('chart-total');
        dom.chartSummary = $('chart-summary');
        dom.canvas = $('trend-canvas');
        dom.chartTooltip = $('chart-tooltip');

        dom.eventsCount = $('events-count');
        dom.eventsBody = $('events-body');
        dom.pagerInfo = $('pager-info');
        dom.btnPrev = $('btn-prev');
        dom.btnNext = $('btn-next');
        dom.filterSeverity = $('filter-severity');
        dom.filterSensor = $('filter-sensor');
        dom.filterStatus = $('filter-status');
        dom.filterQ = $('filter-q');
        dom.btnClearFilters = $('btn-clear-filters');

        dom.sensorList = $('sensor-list');
        dom.sensorCount = $('sensor-count');
        dom.sensorMeta = $('sensor-meta');
        dom.exposureList = $('exposure-list');
        dom.exposureCount = $('exposure-count');
        dom.exposureMeta = $('exposure-meta');
        dom.actionList = $('action-list');
        dom.actionCount = $('action-count');

        dom.hostOs = $('host-os');
        dom.hostUptime = $('host-uptime');
        dom.hostRam = $('host-ram');
        dom.hostDisk = $('host-disk');
        dom.hostCpu = $('host-cpu');
        dom.hostUser = $('host-user');
        dom.hostDb = $('host-db');
        dom.hostDbPath = $('host-db-path');
        dom.hostAutostart = $('host-autostart');
        dom.hostMeta = $('host-meta');
        dom.footerVersion = $('footer-version');

        dom.drawerBackdrop = $('drawer-backdrop');
        dom.eventDrawer = $('event-drawer');
        dom.eventTitle = $('event-drawer-title');
        dom.eventSub = $('event-drawer-sub');
        dom.eventBody = $('event-drawer-body');
        dom.eventFoot = $('event-drawer-foot');
        dom.closeEventDrawer = $('close-event-drawer');

        dom.settingsDrawer = $('settings-drawer');
        dom.closeSettings = $('close-settings');
        dom.setAiEnabled = $('set-ai-enabled');
        dom.setAiModel = $('set-ai-model');
        dom.setToastEnabled = $('set-toast-enabled');
        dom.setToastSeverity = $('set-toast-severity');
        dom.setAutoScan = $('set-auto-scan');
        dom.setAutoBlock = $('set-auto-block');
        dom.setRetention = $('set-retention');
        dom.setCanary = $('set-canary');
        dom.aiEnabledHint = $('ai-enabled-hint');
        dom.btnSaveAiModel = $('btn-save-ai-model');
        dom.btnSaveRetention = $('btn-save-retention');
        dom.btnResetBaseline = $('btn-reset-baseline');
        dom.btnTestToast = $('btn-test-toast');
        dom.btnShutdown = $('btn-shutdown');
    }

    /* ------------------------------------------------------------------ 提示 */
    function showFlash(message, type, force) {
        if (!message || !dom.flashStack) return;
        var kind = type || 'info';
        var key = kind + '|' + String(message);
        var now = Date.now();
        var last = state.flashTimes[key] || 0;
        if (!force && now - last < 12000) return;
        state.flashTimes[key] = now;

        var item = document.createElement('div');
        item.className = 'flash-item ' + kind;
        var icon = document.createElement('span');
        icon.className = 'flash-icon';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = kind === 'ok' ? '✓' : kind === 'err' ? '⚠' : 'ℹ';
        var body = document.createElement('span');
        body.textContent = String(message);
        item.appendChild(icon);
        item.appendChild(body);
        dom.flashStack.appendChild(item);

        while (dom.flashStack.children.length > 3) {
            dom.flashStack.removeChild(dom.flashStack.firstChild);
        }

        var timer = setTimeout(function () {
            item.classList.add('leaving');
            setTimeout(function () {
                if (item.parentNode) item.parentNode.removeChild(item);
            }, 260);
        }, kind === 'err' ? 6500 : 4200);

        item.addEventListener('click', function () {
            clearTimeout(timer);
            if (item.parentNode) item.parentNode.removeChild(item);
        });
    }

    /* ------------------------------------------------------------------ 连接状态 */
    function setConnected(isConnected) {
        if (state.connected === isConnected) return;
        var previous = state.connected;
        state.connected = isConnected;

        dom.connPill.setAttribute('data-state', isConnected ? 'connected' : 'offline');
        dom.connText.textContent = isConnected ? '运行中' : '未连接';
        document.body.classList.toggle('is-offline', !isConnected);

        if (!isConnected && previous === null) {
            showFlash('未连接到哨兵服务：请确认本机 WHX 哨兵已启动（127.0.0.1:8765）', 'err');
        } else if (!isConnected && previous === true) {
            showFlash('与哨兵服务的连接已断开，正在自动重试…', 'err');
        } else if (isConnected && previous === false) {
            showFlash('已恢复与哨兵服务的连接', 'ok');
        }
    }

    /* ------------------------------------------------------------------ API */
    function parseJsonSafe(response) {
        return response.json().catch(function () {
            return null;
        });
    }

    function apiGet(path) {
        return fetch(path, {
            method: 'GET',
            cache: 'no-store',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        }).then(function (response) {
            return parseJsonSafe(response).then(function (data) {
                if (!response.ok) {
                    var message = (data && (data.message || data.detail || data.error)) || ('HTTP ' + response.status);
                    var error = new Error(message);
                    error.status = response.status;
                    throw error;
                }
                return data;
            });
        });
    }

    function getToken(force) {
        if (!force) {
            var cached = storageGet(TOKEN_KEY);
            if (cached) return Promise.resolve(cached);
        }
        if (!state.tokenPromise || force) {
            state.tokenPromise = apiGet('/api/token').then(function (data) {
                var token = data && data.token;
                if (!token) throw new Error('未获取到本机控制令牌');
                storageSet(TOKEN_KEY, String(token));
                return String(token);
            }).finally(function () {
                state.tokenPromise = null;
            });
        }
        return state.tokenPromise;
    }

    function apiWrite(path, payload) {
        return getToken(false).then(function send(token) {
            return fetch(path, {
                method: 'POST',
                cache: 'no-store',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Sentinel-Token': token
                },
                body: JSON.stringify(payload || {})
            }).then(function (response) {
                return parseJsonSafe(response).then(function (data) {
                    if (response.status === 401 || response.status === 403) {
                        storageRemove(TOKEN_KEY);
                        throw new Error('控制令牌无效，请重试');
                    }
                    if (!response.ok) {
                        throw new Error((data && (data.message || data.detail || data.error)) || ('HTTP ' + response.status));
                    }
                    if (data && data.ok === false) {
                        throw new Error(data.message || data.detail || '操作未成功');
                    }
                    return data || { ok: true };
                });
            }).catch(function (error) {
                if (error && error.message === '控制令牌无效，请重试') {
                    return getToken(true).then(function retry(newToken) {
                        return fetch(path, {
                            method: 'POST',
                            cache: 'no-store',
                            credentials: 'same-origin',
                            headers: {
                                'Content-Type': 'application/json',
                                'Accept': 'application/json',
                                'X-Sentinel-Token': newToken
                            },
                            body: JSON.stringify(payload || {})
                        }).then(function (response) {
                            return parseJsonSafe(response).then(function (data) {
                                if (!response.ok) {
                                    throw new Error((data && (data.message || data.detail || data.error)) || ('HTTP ' + response.status));
                                }
                                if (data && data.ok === false) {
                                    throw new Error(data.message || data.detail || '操作未成功');
                                }
                                return data || { ok: true };
                            });
                        });
                    });
                }
                throw error;
            });
        });
    }

    function withButton(button, loadingText, task) {
        if (!button || button.disabled) return Promise.reject(new Error('按钮不可用'));
        var originalHtml = button.innerHTML;
        button.disabled = true;
        button.classList.add('loading');
        button.innerHTML = '<span class="spinner' + (button.classList.contains('btn-danger') ? ' danger' : '') +
            '"></span><span>' + escapeHtml(loadingText) + '</span>';
        return Promise.resolve().then(task).finally(function () {
            button.disabled = false;
            button.classList.remove('loading');
            button.innerHTML = originalHtml;
        });
    }

    /* ------------------------------------------------------------------ 面板片段 */
    function panelEmpty(icon, title, hint, extraClass) {
        return '<div class="panel-empty' + (extraClass ? ' ' + extraClass : '') + '">' +
            '<span class="empty-icon" aria-hidden="true">' + escapeHtml(icon) + '</span>' +
            '<span class="empty-title">' + escapeHtml(title) + '</span>' +
            (hint ? '<span class="empty-hint">' + escapeHtml(hint) + '</span>' : '') +
            '</div>';
    }

    function tableEmptyRow(icon, title, hint) {
        return '<tr><td colspan="6"><div class="table-empty">' +
            '<span class="empty-icon" aria-hidden="true">' + escapeHtml(icon) + '</span>' +
            '<span class="empty-title">' + escapeHtml(title) + '</span>' +
            '<span class="empty-hint">' + escapeHtml(hint) + '</span>' +
            '</div></td></tr>';
    }

    function skeletonRows(count) {
        var html = '';
        for (var i = 0; i < count; i += 1) {
            html += '<tr aria-hidden="true">' +
                '<td><span class="skeleton skeleton-line w70"></span></td>' +
                '<td><span class="skeleton skeleton-line w40"></span></td>' +
                '<td><span class="skeleton skeleton-line w55"></span></td>' +
                '<td><span class="skeleton skeleton-line w85"></span></td>' +
                '<td><span class="skeleton skeleton-line w40"></span></td>' +
                '<td><span class="skeleton skeleton-line w55"></span></td>' +
                '</tr>';
        }
        return html;
    }

    /* ------------------------------------------------------------------ 态势卡片 */
    function setStat(name, value, options) {
        var card = dom.statCards[name];
        if (!card) return;
        var opts = options || {};
        var valueEl = card.querySelector('.stat-value');
        var footEl = card.querySelector('.stat-foot');
        if (!valueEl) return;
        valueEl.classList.toggle('is-text', !!opts.text);
        valueEl.textContent = String(value);
        if (footEl && opts.foot !== undefined) footEl.textContent = String(opts.foot);
        if (opts.tone) {
            card.setAttribute('data-tone', opts.tone);
        } else if (card.hasAttribute('data-tone') && !opts.keepTone) {
            card.removeAttribute('data-tone');
        }
    }

    function severityFoot(count, total) {
        var percent = total > 0 ? Math.round((count / total) * 100) : 0;
        return '占 24h 事件 ' + percent + '%';
    }

    function renderStats(status) {
        var stats = isObject(status.stats) ? status.stats : {};
        var bySeverity = isObject(stats.by_severity) ? stats.by_severity : {};
        var high = Number(stats.high_24h != null ? stats.high_24h : bySeverity.HIGH) || 0;
        var medium = Number(stats.medium_24h != null ? stats.medium_24h : bySeverity.MEDIUM) || 0;
        var low = Number(stats.low_24h != null ? stats.low_24h : bySeverity.LOW) || 0;
        var info = Number(stats.info_24h != null ? stats.info_24h : bySeverity.INFO) || 0;
        var total24 = Number(stats.events_24h != null ? stats.events_24h : high + medium + low + info) || 0;
        var open = Number(stats.open_events) || 0;
        var total = Number(stats.total_events) || 0;

        setStat('high', fmtNum(high), { foot: severityFoot(high, total24) });
        setStat('medium', fmtNum(medium), { foot: severityFoot(medium, total24) });
        setStat('low', fmtNum(low), { foot: severityFoot(low, total24) });
        setStat('info', fmtNum(info), { foot: severityFoot(info, total24) });
        setStat('open', fmtNum(open), { tone: 'accent', foot: open > 0 ? '待确认 · 状态 new' : '全部已处理' });
        setStat('total', fmtNum(total), { tone: 'muted', foot: '数据库全部记录' });

        var sensors = Array.isArray(status.sensors) ? status.sensors : [];
        var online = sensors.filter(function (sensor) {
            var sensorStatus = String(sensor.status || '').toLowerCase();
            return sensorStatus !== 'error' && sensorStatus !== 'stopped';
        }).length;
        var failed = sensors.filter(function (sensor) {
            return String(sensor.status || '').toLowerCase() === 'error';
        }).length;
        setStat('sensors', online + ' / ' + sensors.length, {
            text: true,
            tone: failed > 0 ? 'warn' : (online === sensors.length && sensors.length > 0 ? 'good' : 'warn'),
            foot: sensors.length ? ('共 ' + sensors.length + ' 个 · 异常 ' + failed + ' 个') : '等待传感器'
        });

        renderDefenderCard(status);
        renderFirewallCard(status);
        renderAiCard(status);
    }

    function renderDefenderCard(status) {
        var defender = isObject(status.defender) ? status.defender : {};
        var firewall = isObject(status.firewall) ? status.firewall : (isObject(defender.firewall) ? defender.firewall : {});
        if (!defender.available) {
            setStat('defender', '检测中…', {
                text: true,
                tone: 'muted',
                foot: 'Defender 传感器尚未采集'
            });
        } else if (defender.realtime === false) {
            setStat('defender', '已关闭', {
                text: true,
                tone: 'bad',
                foot: '实时保护未开启，请尽快处理'
            });
        } else if (defender.antivirus === false) {
            setStat('defender', '病毒防护关闭', {
                text: true,
                tone: 'bad',
                foot: '建议在 Windows 安全中心开启'
            });
        } else if (defender.realtime === true) {
            var sigAge = Number(defender.signature_age_days);
            var foot = isFinite(sigAge) ? ('病毒库 ' + sigAge + ' 天前更新') : '实时保护已开启';
            if (defender.engine_version) foot += ' · 引擎 ' + String(defender.engine_version);
            setStat('defender', '已开启', { text: true, tone: 'good', foot: foot });
        } else {
            setStat('defender', '检测中…', {
                text: true,
                tone: 'warn',
                foot: firewall.available ? '正在读取 Defender 状态' : 'Defender 状态读取中'
            });
        }
    }

    function renderFirewallCard(status) {
        var defender = isObject(status.defender) ? status.defender : {};
        var firewall = isObject(status.firewall) ? status.firewall : (isObject(defender.firewall) ? defender.firewall : {});
        if (!firewall.available) {
            setStat('firewall', '检测中…', { text: true, tone: 'muted', foot: '正在读取防火墙状态' });
            return;
        }
        function profileLabel(value) {
            if (value === true) return '开';
            if (value === false) return '关';
            return '—';
        }
        var foot = '域 ' + profileLabel(firewall.domain) + ' · 专用 ' + profileLabel(firewall.private) +
            ' · 公用 ' + profileLabel(firewall.public);
        if (firewall.enabled === true) {
            setStat('firewall', '已启用', { text: true, tone: 'good', foot: foot });
        } else if (firewall.enabled === false) {
            var allOff = firewall.domain === false && firewall.private === false && firewall.public === false;
            setStat('firewall', allOff ? '已关闭' : '部分关闭', { text: true, tone: allOff ? 'bad' : 'warn', foot: foot });
        } else {
            setStat('firewall', '检测中…', { text: true, tone: 'warn', foot: foot });
        }
    }

    function renderAiCard(status) {
        var ai = isObject(status.ai) ? status.ai : {};
        var stats = isObject(status.stats) ? status.stats : {};
        var aiStats = isObject(stats.ai) ? stats.ai : {};
        var enabled = ai.enabled !== undefined ? ai.enabled !== false : !!status.settings && status.settings.ai_enabled !== false;
        var model = text(ai.model || aiStats.model || (status.settings && status.settings.ai_model), '—');
        var done = Number(aiStats.done) || 0;
        var pending = Number(aiStats.pending);
        if (!isFinite(pending)) pending = Number(ai.queue) || 0;
        var available = ai.available !== undefined ? !!ai.available : !!aiStats.available;

        if (!enabled) {
            setStat('ai', '已关闭', { text: true, tone: 'muted', foot: '当前仅展示规则引擎结论' });
        } else if (available) {
            setStat('ai', '可用', {
                text: true,
                tone: 'good',
                foot: '队列 ' + fmtNum(pending) + ' · 已研判 ' + fmtNum(done) + ' · ' + model
            });
        } else {
            setStat('ai', '不可用', {
                text: true,
                tone: 'warn',
                foot: '本机 Ollama 未连接 · 已研判 ' + fmtNum(done) + ' 条'
            });
        }
    }

    /* ------------------------------------------------------------------ 主机信息 */
    function renderHost(status) {
        var host = isObject(status.host) ? status.host : {};
        dom.hostOs.textContent = text(host.os) + (host.os_build ? ' · ' + text(host.os_build) : '');
        dom.hostUptime.textContent = fmtUptime(host.uptime_s != null ? host.uptime_s : status.uptime_s);

        var ramTotal = Number(host.ram_total_mb);
        var ramAvailable = Number(host.ram_available_mb);
        if (isFinite(ramTotal) && ramTotal > 0 && isFinite(ramAvailable)) {
            dom.hostRam.textContent = fmtGbFromMb(ramAvailable) + ' 可用 / ' + fmtGbFromMb(ramTotal);
        } else {
            dom.hostRam.textContent = '—';
        }

        var disk = Number(host.disk_free_gb);
        dom.hostDisk.textContent = isFinite(disk) ? disk + ' GB 可用' : '—';
        var cpu = Number(host.cpu_count);
        dom.hostCpu.textContent = isFinite(cpu) && cpu > 0 ? cpu + ' 核' : '—';
        dom.hostUser.textContent = text(host.user);

        var db = isObject(status.db) ? status.db : {};
        var dbSize = Number(db.size_mb);
        dom.hostDb.textContent = (isFinite(dbSize) ? dbSize + ' MB' : '—') + ' · ' + fmtNum(db.events) + ' 条';
        var dbPath = text(db.path, '—');
        dom.hostDbPath.textContent = dbPath;
        dom.hostDbPath.setAttribute('title', dbPath);

        var autostart = isObject(status.autostart) ? status.autostart : {};
        if (autostart.enabled === true) {
            dom.hostAutostart.textContent = '已启用';
            dom.hostAutostart.setAttribute('title', text(autostart.value, ''));
        } else if (autostart.enabled === false) {
            dom.hostAutostart.textContent = '未启用';
            dom.hostAutostart.setAttribute('title', '');
        } else {
            dom.hostAutostart.textContent = '—';
        }

        var version = text(status.version, '');
        dom.hostMeta.textContent = version ? 'v' + version : '—';
        dom.footerVersion.textContent = 'WHX Sentinel' + (version ? ' v' + version : '') +
            ' · ' + (status.elevated ? '管理员模式' : '标准模式');
        dom.overviewMeta.textContent = '统计窗口：最近 24 小时 · 采样 ' + fmtClock(state.lastStatusAt / 1000);
    }

    /* ------------------------------------------------------------------ 传感器 */
    function sensorDotClass(sensor) {
        var sensorStatus = String(sensor.status || '').toLowerCase();
        var capability = String(sensor.capability || '').toLowerCase();
        if (sensorStatus === 'error' || capability === 'unavailable') return 'error';
        if (sensorStatus === 'stopped') return 'stopped';
        if (capability === 'degraded' || capability === 'needs_admin') return 'degraded';
        if (sensorStatus === 'starting' || capability === 'starting') return 'starting';
        return 'ok';
    }

    function renderSensors(status) {
        var sensors = Array.isArray(status.sensors) ? status.sensors : [];
        state.sensors = sensors;

        if (!sensors.length) {
            dom.sensorList.innerHTML = panelEmpty('📡', '暂无传感器数据', '等待哨兵完成首次采集');
            dom.sensorCount.textContent = '0';
            dom.sensorMeta.textContent = '—';
            return;
        }

        var rows = sensors.map(function (sensor, index) {
            var sensorId = String(sensor.id || ('sensor-' + index));
            var sensorStatus = String(sensor.status || '').toLowerCase();
            var capability = String(sensor.capability || '').toLowerCase();
            var statusLabel = SENSOR_STATUS_LABELS[sensorStatus] || text(sensor.status, '未知');
            var statusTone = SENSOR_STATUS_TONES[sensorStatus] || 'dim';
            var capLabel = CAP_LABELS[capability] || text(sensor.capability, '未知');
            var capTone = CAP_TONES[capability] || 'dim';
            var desc = truncate(text(sensor.description, '暂无描述'), 90);
            var meta = [];
            if (sensor.interval_s != null) meta.push('间隔 ' + fmtSeconds(sensor.interval_s));
            if (sensor.last_run) meta.push('最近 ' + fmtClock(sensor.last_run));
            if (sensor.last_ms != null) meta.push('耗时 ' + fmtMs(sensor.last_ms));
            var needsAdmin = !!sensor.requires_admin && !(state.status && state.status.elevated);

            return '<div class="sensor-item" data-sensor-id="' + escapeHtml(sensorId) + '">' +
                '<span class="sensor-dot ' + escapeHtml(sensorDotClass(sensor)) + '" aria-hidden="true"></span>' +
                '<div class="sensor-main">' +
                '<div class="sensor-top">' +
                '<span class="sensor-name">' + escapeHtml(text(sensor.name || sensor.id, '未命名传感器')) + '</span>' +
                '<span class="badge state-badge ' + escapeHtml(statusTone) + '">' + escapeHtml(statusLabel) + '</span>' +
                (needsAdmin ? '<span class="badge state-badge dim" title="需要以管理员身份运行才能采集">需管理员</span>' : '') +
                '</div>' +
                '<div class="sensor-desc" title="' + escapeHtml(text(sensor.description, '')) + '">' + escapeHtml(desc) + '</div>' +
                '<div class="sensor-meta">' + meta.map(function (item) {
                    return '<span>' + escapeHtml(item) + '</span>';
                }).join('') + '</div>' +
                (sensor.error ? '<div class="sensor-error">' + escapeHtml(truncate(sensor.error, 160)) + '</div>' : '') +
                '</div>' +
                '<div class="sensor-side">' +
                '<span class="badge state-badge ' + escapeHtml(capTone) + '">' + escapeHtml(capLabel) + '</span>' +
                '<span class="cap">' + escapeHtml(sensor.interval_s != null ? '每 ' + fmtSeconds(sensor.interval_s) : '') + '</span>' +
                '</div>' +
                '</div>';
        }).join('');

        dom.sensorList.innerHTML = rows;
        var errorCount = sensors.filter(function (sensor) {
            return String(sensor.status || '').toLowerCase() === 'error';
        }).length;
        var online = sensors.filter(function (sensor) {
            var sensorStatus = String(sensor.status || '').toLowerCase();
            return sensorStatus !== 'error' && sensorStatus !== 'stopped';
        }).length;
        dom.sensorCount.textContent = sensors.length + ' 个';
        dom.sensorMeta.textContent = '在线 ' + online + ' · 异常 ' + errorCount;
    }

    function updateSensorFilterOptions(sensors) {
        if (!dom.filterSensor) return;
        var key = sensors.map(function (sensor) {
            return String(sensor.id) + ':' + text(sensor.name, '');
        }).join('|');
        if (key === state.sensorOptionKey) return;
        state.sensorOptionKey = key;

        var selected = state.filters.sensor;
        var options = ['<option value="">全部</option>'];
        sensors.forEach(function (sensor) {
            var id = text(sensor.id, '');
            if (!id) return;
            options.push('<option value="' + escapeHtml(id) + '">' +
                escapeHtml(text(sensor.name || sensor.id, id)) + '</option>');
        });
        dom.filterSensor.innerHTML = options.join('');
        dom.filterSensor.value = selected;
        if (dom.filterSensor.value !== selected) {
            dom.filterSensor.value = '';
            state.filters.sensor = '';
        }
    }

    /* ------------------------------------------------------------------ 暴露面检查 */
    function renderExposure(status) {
        var exposure = isObject(status.exposure) ? status.exposure : {};
        var checks = Array.isArray(exposure.checks) ? exposure.checks : [];
        var checkedAt = Number(exposure.checked_at);

        if (!checks.length) {
            dom.exposureCount.textContent = '0';
            dom.exposureMeta.textContent = checkedAt > 0 ? '检测于 ' + fmtClock(checkedAt) : '—';
            if (!checkedAt) {
                dom.exposureList.innerHTML = panelEmpty('🛡', '正在检测…', '等待暴露面传感器完成首轮检查');
            } else {
                dom.exposureList.innerHTML = panelEmpty('🛡', '本次未返回检查项', '传感器已完成检查，但没有可展示项');
            }
            return;
        }

        var riskCount = checks.filter(function (check) {
            return !!check.active;
        }).length;
        var rows = checks.map(function (check) {
            var active = !!check.active;
            var severity = normalizeSeverity(check.severity);
            var title = text(check.title, text(check.id, '未命名检查项'));
            var advice = active
                ? (text(check.detail, '') !== '—' ? check.detail : (EXPOSURE_ADVICE[check.id] || '建议尽快确认并关闭该项配置。'))
                : '该项检查通过，未发现该风险配置。';
            return '<div class="check-item' + (active ? ' is-active' : '') + '">' +
                '<span class="check-dot" aria-hidden="true"></span>' +
                '<div class="check-main">' +
                '<div class="check-title">' + escapeHtml(title) + '</div>' +
                '<div class="check-advice">' + escapeHtml(advice) + '</div>' +
                '</div>' +
                '<div class="check-side">' +
                (active
                    ? '<span class="badge sev-badge sev-' + escapeHtml(severity) + '">' + escapeHtml(SEV_LABELS[severity]) + '</span>' +
                      '<span class="badge state-badge bad">风险</span>'
                    : '<span class="badge state-badge good">正常</span>') +
                '</div>' +
                '</div>';
        }).join('');

        dom.exposureList.innerHTML = rows;
        dom.exposureCount.textContent = '风险 ' + riskCount + ' / ' + checks.length;
        dom.exposureMeta.textContent = checkedAt > 0 ? '检测于 ' + fmtClock(checkedAt) : '—';
    }

    /* ------------------------------------------------------------------ 最近处置 */
    function renderActions(actions) {
        if (!Array.isArray(actions) || !actions.length) {
            dom.actionList.innerHTML = '<li class="panel-empty">暂无处置记录</li>';
            dom.actionCount.textContent = '0';
            return;
        }
        dom.actionList.innerHTML = actions.map(function (action) {
            var name = ACTION_LABELS[String(action.action || '')] || text(action.action, '操作');
            var target = text(action.target, '');
            var eventId = Number(action.event_id);
            var hasEvent = Number.isFinite(eventId) && eventId > 0;
            var ok = !!action.ok;
            return '<li class="action-item' + (hasEvent ? ' clickable' : '') + '"' +
                (hasEvent ? ' data-event-id="' + eventId + '" tabindex="0" role="button"' : '') + '>' +
                '<span class="action-time">' + escapeHtml(fmtClock(action.ts)) + '</span>' +
                '<span class="action-name">' + escapeHtml(name) +
                (target ? ' <span class="target">' + escapeHtml(truncate(target, 40)) + '</span>' : '') +
                (hasEvent ? ' <span class="target">#' + eventId + '</span>' : '') +
                '</span>' +
                '<span class="action-result ' + (ok ? 'ok' : 'fail') + '">' + (ok ? '成功' : '失败') + '</span>' +
                '</li>';
        }).join('');
        dom.actionCount.textContent = actions.length + ' 条';
    }

    /* ------------------------------------------------------------------ 趋势图 */
    function niceCeil(value) {
        if (!isFinite(value) || value <= 0) return 4;
        var exponent = Math.floor(Math.log10(value));
        var factor = value / Math.pow(10, exponent);
        var niceFactor;
        if (factor <= 1) niceFactor = 1;
        else if (factor <= 2) niceFactor = 2;
        else if (factor <= 5) niceFactor = 5;
        else niceFactor = 10;
        return niceFactor * Math.pow(10, exponent);
    }

    function drawChart() {
        var canvas = dom.canvas;
        if (!canvas || !canvas.getContext) return;
        var ctx = canvas.getContext('2d');
        if (!ctx) return;

        var cssWidth = Math.max(280, canvas.clientWidth || 600);
        var cssHeight = Math.max(160, canvas.clientHeight || 240);
        var dpr = Math.min(window.devicePixelRatio || 1, 2.5);
        var pixelWidth = Math.round(cssWidth * dpr);
        var pixelHeight = Math.round(cssHeight * dpr);
        if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
            canvas.width = pixelWidth;
            canvas.height = pixelHeight;
        }
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, cssWidth, cssHeight);

        var pad = { left: 36, right: 10, top: 12, bottom: 24 };
        var plotW = Math.max(20, cssWidth - pad.left - pad.right);
        var plotH = Math.max(20, cssHeight - pad.top - pad.bottom);

        function centerLabel(message, color) {
            ctx.fillStyle = color || '#64748b';
            ctx.font = '12px ' + getComputedStyle(document.body).fontFamily;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(message, cssWidth / 2, cssHeight / 2);
        }

        var buckets = Array.isArray(state.timeline) ? state.timeline : null;
        if (buckets === null) {
            centerLabel('趋势数据加载中…');
            state.chartGeom = null;
            return;
        }

        var totals = buckets.map(function (bucket) {
            return STACK_ORDER.reduce(function (sum, severity) {
                return sum + (Number(bucket[severity]) || 0);
            }, 0);
        });
        var maxTotal = totals.reduce(function (max, value) {
            return Math.max(max, value);
        }, 0);
        var gridMax = maxTotal > 0 ? niceCeil(maxTotal) : 4;

        ctx.font = '9px ' + getComputedStyle(document.body).fontFamily;
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for (var line = 0; line <= 4; line += 1) {
            var value = Math.round((gridMax / 4) * line);
            var y = pad.top + plotH - (plotH / 4) * line;
            ctx.strokeStyle = line === 0 ? 'rgba(148, 163, 184, 0.25)' : 'rgba(148, 163, 184, 0.1)';
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(pad.left, y + 0.5);
            ctx.lineTo(pad.left + plotW, y + 0.5);
            ctx.stroke();
            ctx.fillStyle = '#64748b';
            ctx.fillText(String(value), pad.left - 7, y);
        }

        if (!buckets.length) {
            centerLabel('暂无趋势数据');
            state.chartGeom = null;
            return;
        }

        var count = buckets.length;
        var slot = plotW / count;
        var barW = Math.min(22, Math.max(4, slot * 0.62));
        state.chartGeom = { left: pad.left, top: pad.top, plotW: plotW, plotH: plotH, slot: slot, count: count };

        buckets.forEach(function (bucket, index) {
            var centerX = pad.left + slot * (index + 0.5);
            var x = centerX - barW / 2;
            var y = pad.top + plotH;
            if (state.chartHover === index) {
                ctx.fillStyle = 'rgba(56, 189, 248, 0.07)';
                ctx.fillRect(centerX - slot / 2, pad.top, slot, plotH);
            }
            STACK_ORDER.forEach(function (severity) {
                var amount = Number(bucket[severity]) || 0;
                if (amount <= 0) return;
                var barHeight = Math.max(1.2, (amount / gridMax) * plotH);
                y -= barHeight;
                ctx.fillStyle = SEV_COLORS[severity];
                ctx.globalAlpha = 0.88;
                ctx.fillRect(x, y, barW, barHeight);
                ctx.globalAlpha = 1;
            });
            if (totals[index] === 0) {
                ctx.fillStyle = 'rgba(148, 163, 184, 0.16)';
                ctx.fillRect(x, pad.top + plotH - 1, barW, 1);
            }
        });

        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = '#64748b';
        var labelStep = Math.max(1, Math.ceil(count / Math.max(2, Math.floor(plotW / 58))));
        buckets.forEach(function (bucket, index) {
            if (index % labelStep !== 0 && index !== count - 1) return;
            var x = pad.left + slot * (index + 0.5);
            ctx.fillText(text(bucket.label, ''), x, pad.top + plotH + 7);
        });

        if (maxTotal === 0) {
            centerLabel('过去 24 小时暂无事件', '#475569');
        }
    }

    function updateChartSummary() {
        var buckets = Array.isArray(state.timeline) ? state.timeline : [];
        var total = 0;
        var peak = null;
        var peakTotal = 0;
        buckets.forEach(function (bucket) {
            var sum = STACK_ORDER.reduce(function (acc, severity) {
                return acc + (Number(bucket[severity]) || 0);
            }, 0);
            total += sum;
            if (sum > peakTotal) {
                peakTotal = sum;
                peak = bucket;
            }
        });
        if (dom.chartTotal) dom.chartTotal.textContent = fmtNum(total) + ' 条';
        if (!dom.chartSummary) return;
        if (!buckets.length) {
            dom.chartSummary.textContent = '过去 24 小时暂无趋势数据';
            return;
        }
        if (!total) {
            dom.chartSummary.textContent = '过去 24 小时暂无事件';
            return;
        }
        dom.chartSummary.innerHTML = '24 小时共 <strong>' + escapeHtml(fmtNum(total)) + '</strong> 条事件' +
            (peak ? ' · 峰值 <strong>' + escapeHtml(text(peak.label, '—')) + '</strong>（' +
                escapeHtml(fmtNum(peakTotal)) + ' 条）' : '');
    }

    function resizeChart() {
        drawChart();
    }

    function showChartTooltip(clientX, clientY, index) {
        var geom = state.chartGeom;
        var tooltip = dom.chartTooltip;
        var canvas = dom.canvas;
        if (!geom || !tooltip || !canvas) return;
        var bucket = state.timeline[index];
        if (!bucket) return;
        var rows = STACK_ORDER.map(function (severity) {
            return '<div class="tt-row"><span><span class="legend-dot sev-' + severity + '"></span>' +
                escapeHtml(SEV_LABELS[severity]) + '</span><b>' + escapeHtml(fmtNum(bucket[severity] || 0)) + '</b></div>';
        }).join('');
        var total = STACK_ORDER.reduce(function (sum, severity) {
            return sum + (Number(bucket[severity]) || 0);
        }, 0);
        tooltip.innerHTML = '<div class="tt-head">' + escapeHtml(text(bucket.label, '—')) + ' · 共 ' +
            escapeHtml(fmtNum(total)) + ' 条</div>' + rows;

        var wrap = canvas.parentElement;
        var wrapRect = wrap.getBoundingClientRect();
        var left = canvas.offsetLeft + geom.left + geom.slot * (index + 0.5);
        var top = canvas.offsetTop + (clientY - wrapRect.top) - 12;
        left = Math.max(78, Math.min(wrapRect.width - 78, left));
        top = Math.max(46, top);
        tooltip.style.left = left + 'px';
        tooltip.style.top = top + 'px';
        tooltip.hidden = false;
    }

    function hideChartTooltip() {
        if (dom.chartTooltip) dom.chartTooltip.hidden = true;
    }

    function handleChartMove(event) {
        var geom = state.chartGeom;
        var canvas = dom.canvas;
        if (!geom || !canvas) return;
        var rect = canvas.getBoundingClientRect();
        var x = event.clientX - rect.left;
        var index = Math.floor((x - geom.left) / geom.slot);
        var inside = x >= geom.left && x <= geom.left + geom.plotW && index >= 0 && index < geom.count;
        var next = inside ? index : -1;
        if (next !== state.chartHover) {
            state.chartHover = next;
            drawChart();
        }
        if (next >= 0) {
            showChartTooltip(event.clientX, event.clientY, next);
        } else {
            hideChartTooltip();
        }
    }

    function handleChartLeave() {
        if (state.chartHover !== -1) {
            state.chartHover = -1;
            drawChart();
        }
        hideChartTooltip();
    }

    function loadTimeline() {
        return apiGet('/api/timeline?hours=24').then(function (data) {
            state.timeline = Array.isArray(data && data.buckets) ? data.buckets : [];
            drawChart();
            updateChartSummary();
        }).catch(function () {
            if (!state.timeline) {
                state.timeline = [];
                drawChart();
                updateChartSummary();
            }
        });
    }

    /* ------------------------------------------------------------------ 事件列表 */
    function buildEventsQuery() {
        var params = new URLSearchParams();
        params.set('limit', String(PAGE_SIZE));
        params.set('offset', String(state.offset));
        params.set('hours', '24');
        if (state.filters.severity) params.set('severity', state.filters.severity);
        if (state.filters.sensor) params.set('sensor', state.filters.sensor);
        if (state.filters.status) params.set('status', state.filters.status);
        if (state.filters.q) params.set('q', state.filters.q);
        return '/api/events?' + params.toString();
    }

    function syncActiveRow() {
        if (!dom.eventsBody) return;
        var currentId = state.currentEvent ? Number(state.currentEvent.id) : null;
        Array.prototype.forEach.call(dom.eventsBody.querySelectorAll('tr[data-id]'), function (row) {
            var isActive = currentId !== null && Number(row.getAttribute('data-id')) === currentId;
            row.classList.toggle('is-active', isActive);
        });
    }

    function renderEvents() {
        var events = state.events;
        if (!events.length) {
            var hasFilters = state.filters.severity || state.filters.sensor || state.filters.status || state.filters.q;
            dom.eventsBody.innerHTML = hasFilters
                ? tableEmptyRow('🔎', '当前筛选条件下没有事件', '尝试放宽筛选条件或点击「清除筛选」。')
                : tableEmptyRow('🛡', '最近 24 小时内暂无安全事件', '哨兵正在后台采集；如刚启动请稍候，页面会自动刷新。');
            dom.eventsCount.textContent = '0 条';
            state.eventsRenderedOnce = true;
            syncActiveRow();
            return;
        }

        dom.eventsBody.innerHTML = events.map(function (event) {
            var id = Number(event.id);
            if (!isFinite(id)) return '';
            var severity = normalizeSeverity(event.severity);
            var status = normalizeStatus(event.status);
            var seen = Number(event.seen_count);
            if (!isFinite(seen) || seen < 1) seen = 1;
            var excerpt = truncate(text(event.detail, '') !== '—' ? event.detail : text(event.subject, ''), 90);
            return '<tr data-id="' + id + '" tabindex="0">' +
                '<td class="cell-time">' + escapeHtml(fmtEventTime(event)) + '</td>' +
                '<td><span class="badge sev-badge sev-' + severity + '">' + escapeHtml(SEV_LABELS[severity]) + '</span></td>' +
                '<td class="cell-sensor">' + escapeHtml(text(event.sensor, '—')) + '</td>' +
                '<td class="cell-title"><span class="ev-title">' + escapeHtml(text(event.title, '未命名事件')) + '</span>' +
                (excerpt ? '<span class="ev-excerpt">' + escapeHtml(excerpt) + '</span>' : '') + '</td>' +
                '<td class="cell-repeat">' + (seen > 1 ? '×<b>' + escapeHtml(fmtNum(seen)) + '</b>' : '×1') + '</td>' +
                '<td class="cell-status"><span class="badge status-badge status-' + status + '">' +
                escapeHtml(STATUS_LABELS[status]) + '</span></td>' +
                '</tr>';
        }).join('');

        dom.eventsCount.textContent = fmtNum(state.eventsTotal) + ' 条';
        state.eventsRenderedOnce = true;
        syncActiveRow();
    }

    function renderPager() {
        var total = state.eventsTotal;
        var offset = state.offset;
        var pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        var page = Math.floor(offset / PAGE_SIZE) + 1;
        var start = total > 0 ? offset + 1 : 0;
        var end = Math.min(offset + PAGE_SIZE, total);
        dom.pagerInfo.innerHTML = total > 0
            ? '第 <strong>' + page + '</strong> / ' + pages + ' 页 · ' +
              fmtNum(start) + '–' + fmtNum(end) + ' 条 · 共 <strong>' + fmtNum(total) + '</strong> 条'
            : '暂无事件';
        dom.btnPrev.disabled = offset <= 0;
        dom.btnNext.disabled = offset + PAGE_SIZE >= total;
    }

    function renderEventsUnavailable(message) {
        dom.eventsBody.innerHTML = tableEmptyRow('📡', '事件数据暂不可用', message || '正在自动重试…');
        dom.eventsCount.textContent = '—';
        dom.pagerInfo.textContent = '—';
        dom.btnPrev.disabled = true;
        dom.btnNext.disabled = true;
    }

    function loadEvents() {
        if (state.polling.events) return Promise.resolve();
        if (document.hidden && state.eventsRenderedOnce) return Promise.resolve();
        state.polling.events = true;
        return apiGet(buildEventsQuery()).then(function (data) {
            state.events = Array.isArray(data && data.events) ? data.events : [];
            state.eventsTotal = Number(data && data.total) || 0;
            var maxOffset = Math.max(0, Math.ceil(state.eventsTotal / PAGE_SIZE) - 1) * PAGE_SIZE;
            if (state.offset > maxOffset) {
                state.offset = maxOffset;
                state.polling.events = false;
                return loadEvents();
            }
            renderEvents();
            renderPager();
        }).catch(function (error) {
            if (!state.eventsRenderedOnce && state.connected === false) {
                renderEventsUnavailable('等待本机哨兵服务启动后自动恢复…');
            } else if (state.connected !== false) {
                showFlash('事件列表刷新失败：' + describeError(error), 'err');
            }
        }).finally(function () {
            state.polling.events = false;
        });
    }

    /* ------------------------------------------------------------------ 事件详情 */
    function getEventPid(metadata) {
        if (!isObject(metadata)) return null;
        var pid = Number(metadata.pid);
        return isValidPid(pid) ? pid : null;
    }

    function getEventIp(metadata) {
        if (!isObject(metadata)) return null;
        var ip = String(metadata.remote_ip || '').trim();
        return isValidIp(ip) ? ip : null;
    }

    function renderAiBox(event, pending) {
        var engine = text(event && event.ai_engine, '');
        var box = dom.eventBody.querySelector('.ai-box');
        if (!box) return;
        box.classList.toggle('is-pending', !!pending);
        var heading = '<h3>AI 研判' + (engine ? ' <span class="ai-engine">' + escapeHtml(engine) + '</span>' : '') + '</h3>';
        var note = text(event && event.ai_note, '');
        var content;
        if (pending) {
            content = '<div class="ai-waiting"><span class="spinner"></span><span>AI 分析中…（本机模型可能需要 1–2 分钟，请稍候）</span></div>';
        } else if (note) {
            content = '<div class="ai-note">' + escapeHtml(note) + '</div>';
        } else {
            content = '<div class="ai-empty">尚未进行 AI 研判。点击下方「AI 研判」调用本机 Ollama 模型（仅高危事件会自动进入队列）。</div>';
        }
        box.innerHTML = heading + content;
    }

    function renderEventFooter(event, metadata, status) {
        var pid = getEventPid(metadata);
        var ip = getEventIp(metadata);
        var html = '';
        html += '<button class="btn btn-sm ' + (status === 'ack' ? 'btn-muted' : 'btn-safe') +
            '" type="button" data-action="ack_event"' + (status === 'ack' ? ' disabled' : '') + '>✓ 确认事件</button>';
        html += '<button class="btn btn-sm btn-muted" type="button" data-action="ignore_event"' +
            (status === 'ignored' ? ' disabled' : '') + '>忽略事件</button>';
        html += '<button class="btn btn-sm btn-link" type="button" data-action="ai_analyze">🧠 AI 研判</button>';
        if (pid) {
            html += '<button class="btn btn-sm btn-danger" type="button" data-action="kill_process" data-pid="' +
                pid + '">结束进程 PID ' + pid + '</button>';
        }
        if (ip) {
            html += '<button class="btn btn-sm btn-danger" type="button" data-action="block_ip" data-ip="' +
                escapeHtml(ip) + '">封锁 IP ' + escapeHtml(ip) + '</button>';
        }
        if (!pid && !ip) {
            html += '<span class="drawer-hint">该事件未提供进程 PID / 远端 IP，无法直接处置</span>';
        }
        dom.eventFoot.innerHTML = html;
        dom.eventFoot.hidden = false;
    }

    function renderEventDetail(event) {
        if (!event) return;
        state.currentEvent = event;
        var id = Number(event.id);
        var severity = normalizeSeverity(event.severity);
        var status = normalizeStatus(event.status);
        var metadata = isObject(event.metadata) ? event.metadata : {};

        dom.eventTitle.innerHTML = '<span class="badge sev-badge sev-' + severity + '">' +
            escapeHtml(SEV_LABELS[severity]) + '</span><span>' + escapeHtml(text(event.title, '未命名事件')) + '</span>';
        dom.eventSub.textContent = '#' + text(id, '—') + ' · ' + text(event.sensor, '—') + ' · ' + fmtEventTime(event);

        var seen = Number(event.seen_count);
        if (!isFinite(seen) || seen < 1) seen = 1;
        var subject = text(event.subject, '—');
        var ruleId = text(event.rule_id, '—');
        var detail = text(event.detail, '') !== '—' ? event.detail : '（无详细描述）';

        dom.eventBody.innerHTML =
            '<dl class="detail-meta">' +
                '<div><dt>时间</dt><dd>' + escapeHtml(text(event.day, '') + (event.time ? ' ' + event.time : '')) + '</dd></div>' +
                '<div><dt>传感器</dt><dd>' + escapeHtml(text(event.sensor, '—')) + '</dd></div>' +
                '<div><dt>严重度</dt><dd>' + escapeHtml(severity + ' · ' + SEV_LABELS[severity]) + '</dd></div>' +
                '<div><dt>状态</dt><dd>' + escapeHtml(STATUS_LABELS[status]) + '</dd></div>' +
                '<div><dt>规则</dt><dd>' + escapeHtml(ruleId) + '</dd></div>' +
                '<div><dt>主题</dt><dd>' + escapeHtml(subject) + '</dd></div>' +
                '<div><dt>重复次数</dt><dd>' + escapeHtml(fmtNum(seen)) + ' 次</dd></div>' +
                '<div><dt>首次 / 最近</dt><dd>' + escapeHtml(fmtDateTime(event.first_ts)) + '<br>' +
                    escapeHtml(fmtDateTime(event.last_ts || event.ts)) + '</dd></div>' +
            '</dl>' +
            '<section class="detail-section"><h3>事件详情</h3>' +
                '<p class="detail-text">' + escapeHtml(detail) + '</p></section>' +
            '<section class="detail-section"><h3>结构化信息 · metadata</h3>' +
                '<pre class="metadata-json" id="event-metadata-json"></pre></section>' +
            '<section class="detail-section ai-box"><h3>AI 研判</h3></section>';

        var pre = dom.eventBody.querySelector('.metadata-json');
        if (pre) {
            var metadataText;
            try {
                metadataText = JSON.stringify(metadata, null, 2);
            } catch (error) {
                metadataText = String(metadata);
            }
            if (!metadataText || metadataText === '{}') metadataText = '（无结构化信息）';
            pre.textContent = metadataText;
        }

        renderAiBox(event, false);
        renderEventFooter(event, metadata, status);
        syncActiveRow();
    }

    function renderEventDetailError(message) {
        dom.eventTitle.textContent = '事件详情不可用';
        dom.eventSub.textContent = message || '加载失败，请稍后重试';
        dom.eventBody.innerHTML = panelEmpty('⚠', '无法加载事件详情', message || '本地 API 请求失败');
        dom.eventFoot.hidden = true;
    }

    function openEvent(eventId, trigger) {
        var id = Number(eventId);
        if (!isFinite(id)) return;
        if (state.activeDrawer !== dom.eventDrawer) openDrawer(dom.eventDrawer, trigger);
        state.eventDrawerOpen = true;
        state.eventRequestSeq += 1;
        var requestId = state.eventRequestSeq;
        state.currentEvent = null;

        dom.eventTitle.textContent = '正在加载事件 #' + id + '…';
        dom.eventSub.textContent = '读取详情…';
        dom.eventBody.innerHTML = '<div class="skeleton-list">' +
            '<div class="skeleton-row"><span class="skeleton skeleton-line w55"></span></div>' +
            '<div class="skeleton-row"><span class="skeleton skeleton-line w85"></span></div>' +
            '<div class="skeleton-row"><span class="skeleton skeleton-line w70"></span></div>' +
            '<div class="skeleton-row"><span class="skeleton skeleton-line w40"></span></div>' +
            '</div>';
        dom.eventFoot.hidden = true;
        syncActiveRow();

        var cached = state.events.find(function (item) {
            return Number(item.id) === id;
        });
        if (cached) renderEventDetail(cached);

        apiGet('/api/events/' + encodeURIComponent(String(id))).then(function (fresh) {
            if (requestId !== state.eventRequestSeq || !state.eventDrawerOpen) return;
            if (fresh && Number(fresh.id)) renderEventDetail(fresh);
        }).catch(function () {
            if (requestId !== state.eventRequestSeq || !state.eventDrawerOpen) return;
            if (!cached) renderEventDetailError('事件详情加载失败，请稍后重试');
            else showFlash('事件详情刷新失败，显示的是列表缓存', 'err');
        });
    }

    function refreshCurrentEvent() {
        var event = state.currentEvent;
        if (!event) return Promise.resolve();
        var id = Number(event.id);
        if (!isFinite(id)) return Promise.resolve();
        return apiGet('/api/events/' + encodeURIComponent(String(id))).then(function (fresh) {
            if (fresh && Number(fresh.id) && state.eventDrawerOpen &&
                state.currentEvent && Number(state.currentEvent.id) === id) {
                renderEventDetail(fresh);
            }
        }).catch(function () {
            /* 静默：下次轮询会刷新列表 */
        });
    }

    function handleEventActionClick(event) {
        var button = event.target.closest('button[data-action]');
        if (!button || !dom.eventFoot.contains(button)) return;
        var action = button.getAttribute('data-action');
        var current = state.currentEvent;
        if (!current) return;
        var eventId = Number(current.id);
        if (!isFinite(eventId)) return;

        var path = '/api/actions/' + action;
        var payload = { event_id: eventId };
        var loadingText = '处理中…';
        var confirmText = '';

        if (action === 'ack_event') {
            loadingText = '确认中…';
        } else if (action === 'ignore_event') {
            loadingText = '忽略中…';
        } else if (action === 'ai_analyze') {
            loadingText = 'AI 分析中…';
            payload = { event_id: eventId };
            renderAiBox(current, true);
        } else if (action === 'kill_process') {
            var pid = Number(button.getAttribute('data-pid'));
            if (!isValidPid(pid)) {
                showFlash('无效的进程 PID', 'err', true);
                return;
            }
            loadingText = '正在结束进程…';
            confirmText = '确定要结束进程 PID ' + pid + ' 吗？\n该操作立即生效且不可撤销。';
            payload = { pid: pid, event_id: eventId };
        } else if (action === 'block_ip') {
            var ip = String(button.getAttribute('data-ip') || '');
            if (!isValidIp(ip)) {
                showFlash('无效的远端 IP', 'err', true);
                return;
            }
            loadingText = '正在封锁 IP…';
            confirmText = '确定要封锁远端 IP ' + ip + ' 吗？\n将通过本机 Windows 防火墙阻断该地址。';
            payload = { ip: ip, event_id: eventId };
        } else {
            return;
        }

        if (confirmText && !window.confirm(confirmText)) return;

        withButton(button, loadingText, function () {
            return apiWrite(path, payload).then(function (data) {
                showFlash((data && (data.message || data.detail)) || '操作成功', 'ok', true);
                return data;
            });
        }).catch(function (error) {
            showFlash('操作失败：' + describeError(error), 'err', true);
            if (action === 'ai_analyze' && state.currentEvent) renderAiBox(state.currentEvent, false);
        }).finally(function () {
            refreshCurrentEvent();
            loadEvents();
            loadStatus();
            loadActions();
            loadTimeline();
        });
    }

    function openDrawer(drawer, trigger) {
        if (!drawer) return;
        if (state.activeDrawer === drawer) return;
        var previous = state.activeDrawer;
        if (previous) {
            previous.classList.remove('open');
            hideDrawerSoon(previous);
        }
        state.eventDrawerOpen = false;
        state.settingsDrawerOpen = false;
        dom.btnSettings.setAttribute('aria-expanded', 'false');
        drawer.hidden = false;
        dom.drawerBackdrop.hidden = false;
        document.body.style.overflow = 'hidden';
        state.activeDrawer = drawer;
        state.drawerTrigger = trigger || document.activeElement;
        window.requestAnimationFrame(function () {
            drawer.classList.add('open');
        });
        var closeButton = drawer.querySelector('.drawer-close');
        if (closeButton) {
            window.setTimeout(function () {
                try {
                    closeButton.focus();
                } catch (error) {
                    /* ignore */
                }
            }, 80);
        }
    }

    function hideDrawerSoon(drawer) {
        if (!drawer) return;
        window.clearTimeout(drawer._hideTimer);
        drawer._hideTimer = window.setTimeout(function () {
            if (!drawer.classList.contains('open')) drawer.hidden = true;
        }, 320);
    }

    function closeDrawers(silent) {
        var drawer = state.activeDrawer;
        if (!drawer) return;
        drawer.classList.remove('open');
        hideDrawerSoon(drawer);
        dom.drawerBackdrop.hidden = true;
        document.body.style.overflow = '';
        state.activeDrawer = null;
        state.eventDrawerOpen = false;
        state.settingsDrawerOpen = false;
        dom.btnSettings.setAttribute('aria-expanded', 'false');
        if (drawer === dom.eventDrawer) {
            state.eventRequestSeq += 1;
            state.currentEvent = null;
            syncActiveRow();
        }
        var trigger = state.drawerTrigger;
        state.drawerTrigger = null;
        if (!silent && trigger && typeof trigger.focus === 'function') {
            try {
                trigger.focus();
            } catch (error) {
                /* ignore */
            }
        }
    }

    /* ------------------------------------------------------------------ 设置抽屉 */
    function getAllowlist(kind) {
        var settings = state.settings;
        if (!settings || !isObject(settings.allowlist)) return [];
        var list = settings.allowlist[kind];
        return Array.isArray(list) ? list.slice() : [];
    }

    function setAllowlist(kind, values) {
        if (!state.settings) state.settings = {};
        if (!isObject(state.settings.allowlist)) state.settings.allowlist = {};
        state.settings.allowlist[kind] = values;
    }

    function renderAllowlistKind(kind) {
        var listEl = $('allow-list-' + kind);
        if (!listEl) return;
        var values = getAllowlist(kind);
        if (!values.length) {
            listEl.innerHTML = '<li class="allow-empty">暂无条目</li>';
            return;
        }
        listEl.innerHTML = values.map(function (value) {
            var raw = String(value);
            return '<li class="allow-chip">' +
                '<span class="chip-value" title="' + escapeHtml(raw) + '">' + escapeHtml(truncate(raw, 70)) + '</span>' +
                '<button class="chip-remove" type="button" data-kind="' + escapeHtml(kind) +
                '" data-value="' + escapeHtml(raw) + '" aria-label="移除白名单 ' + escapeHtml(raw) + '">✕</button>' +
                '</li>';
        }).join('');
    }

    function renderAllowlist() {
        ALLOW_KINDS.forEach(renderAllowlistKind);
    }

    function populateSettings() {
        var status = state.status;
        var settings = status && isObject(status.settings) ? status.settings : null;
        if (!settings) {
            state.settingsPopulated = false;
            dom.aiEnabledHint.textContent = '等待状态数据…';
            return false;
        }
        state.settings = settings;
        dom.setAiEnabled.checked = !!settings.ai_enabled;
        var aiInfo = isObject(status.ai) ? status.ai : {};
        dom.setAiModel.value = text(settings.ai_model || aiInfo.model, '');
        dom.setToastEnabled.checked = !!settings.toast_enabled;
        var toastSeverity = String(settings.toast_min_severity || 'HIGH').toUpperCase();
        dom.setToastSeverity.value = SEV_LABELS[toastSeverity] ? toastSeverity : 'HIGH';
        dom.setAutoScan.checked = !!settings.auto_quick_scan_on_malware;
        dom.setAutoBlock.checked = !!settings.auto_block_high_remote;
        var retention = Number(settings.retention_days);
        dom.setRetention.value = isFinite(retention) && retention > 0 ? String(Math.round(retention)) : '30';
        dom.setCanary.checked = !!settings.canary_enabled;

        var ai = isObject(status.ai) ? status.ai : {};
        if (ai.enabled === false || settings.ai_enabled === false) {
            dom.aiEnabledHint.textContent = 'AI 已关闭：只展示规则引擎结论';
        } else if (ai.available) {
            dom.aiEnabledHint.textContent = '本机 Ollama 可用' + (ai.model ? ' · 模型 ' + ai.model : '');
        } else {
            dom.aiEnabledHint.textContent = '本机 Ollama 不可用：研判按钮会返回失败提示';
        }
        renderAllowlist();
        state.settingsPopulated = true;
        return true;
    }

    function openSettings(trigger) {
        if (state.activeDrawer !== dom.settingsDrawer) openDrawer(dom.settingsDrawer, trigger);
        state.settingsDrawerOpen = true;
        dom.btnSettings.setAttribute('aria-expanded', 'true');
        state.settingsPopulated = false;
        if (!populateSettings()) {
            showFlash('设置尚未加载：正在等待状态数据…', 'info');
        }
    }

    function saveToggle(input, key, label, toneWhenOn) {
        if (!input) return Promise.resolve();
        var nextValue = input.checked;
        input.disabled = true;
        return apiWrite('/api/settings', (function () {
            var patch = {};
            patch[key] = nextValue;
            return patch;
        })()).then(function (data) {
            if (data && isObject(data.settings)) state.settings = data.settings;
            else if (state.settings) state.settings[key] = nextValue;
            showFlash(label + (nextValue ? '已开启' : '已关闭'), 'ok', true);
            loadStatus();
        }).catch(function (error) {
            input.checked = !nextValue;
            showFlash('保存「' + label + '」失败：' + describeError(error), 'err', true);
        }).finally(function () {
            input.disabled = false;
        });
    }

    function saveToastSeverity() {
        var select = dom.setToastSeverity;
        var nextValue = select.value;
        select.disabled = true;
        return apiWrite('/api/settings', { toast_min_severity: nextValue }).then(function (data) {
            if (data && isObject(data.settings)) state.settings = data.settings;
            else if (state.settings) state.settings.toast_min_severity = nextValue;
            showFlash('最低通知级别已设为「' + (SEV_LABELS[nextValue] || nextValue) + '」', 'ok', true);
        }).catch(function (error) {
            if (state.settings && SEV_LABELS[state.settings.toast_min_severity]) {
                select.value = state.settings.toast_min_severity;
            }
            showFlash('保存通知级别失败：' + describeError(error), 'err', true);
        }).finally(function () {
            select.disabled = false;
        });
    }

    function saveAiModel() {
        var value = dom.setAiModel.value.trim();
        if (!value) {
            showFlash('请输入模型名称', 'err', true);
            dom.setAiModel.focus();
            return;
        }
        withButton(dom.btnSaveAiModel, '保存中…', function () {
            return apiWrite('/api/settings', { ai_model: value }).then(function (data) {
                if (data && isObject(data.settings)) state.settings = data.settings;
                else if (state.settings) state.settings.ai_model = value;
                showFlash('AI 模型已设为 ' + value, 'ok', true);
                loadStatus();
            });
        }).catch(function (error) {
            showFlash('保存 AI 模型失败：' + describeError(error), 'err', true);
        });
    }

    function saveRetention() {
        var value = Number(dom.setRetention.value);
        if (!Number.isInteger(value) || value < 1 || value > 365) {
            showFlash('保留天数需为 1–365 的整数', 'err', true);
            dom.setRetention.focus();
            return;
        }
        withButton(dom.btnSaveRetention, '保存中…', function () {
            return apiWrite('/api/settings', { retention_days: value }).then(function (data) {
                if (data && isObject(data.settings)) state.settings = data.settings;
                else if (state.settings) state.settings.retention_days = value;
                showFlash('数据保留天数已设为 ' + value + ' 天', 'ok', true);
                loadStatus();
            });
        }).catch(function (error) {
            showFlash('保存保留天数失败：' + describeError(error), 'err', true);
        });
    }

    function addAllowlistEntry(kind, button) {
        var input = $('allow-input-' + kind);
        if (!input) return;
        var value = input.value.trim();
        if (!value) {
            showFlash('请输入要加入白名单的值', 'err', true);
            input.focus();
            return;
        }
        var values = getAllowlist(kind);
        var duplicate = values.some(function (item) {
            return String(item) === value;
        });
        if (duplicate) {
            showFlash('该值已在' + (ALLOW_LABELS[kind] || '白名单') + '中', 'info', true);
            input.select();
            return;
        }
        withButton(button, '添加中…', function () {
            return apiWrite('/api/allowlist', { action: 'add', kind: kind, value: value }).then(function (data) {
                if (data && isObject(data.allowlist)) {
                    if (!state.settings) state.settings = {};
                    state.settings.allowlist = data.allowlist;
                } else {
                    values.push(value);
                    setAllowlist(kind, values);
                }
                renderAllowlistKind(kind);
                input.value = '';
                showFlash('已加入白名单：' + value, 'ok', true);
                loadStatus();
            });
        }).catch(function (error) {
            showFlash('添加白名单失败：' + describeError(error), 'err', true);
        });
    }

    function removeAllowlistEntry(kind, value) {
        var values = getAllowlist(kind);
        return apiWrite('/api/allowlist', { action: 'remove', kind: kind, value: value }).then(function (data) {
            if (data && isObject(data.allowlist)) {
                if (!state.settings) state.settings = {};
                state.settings.allowlist = data.allowlist;
            } else {
                setAllowlist(kind, values.filter(function (item) {
                    return String(item) !== value;
                }));
            }
            renderAllowlistKind(kind);
            showFlash('已移除白名单：' + value, 'ok', true);
            loadStatus();
        }).catch(function (error) {
            showFlash('移除白名单失败：' + describeError(error), 'err', true);
        });
    }

    function runSimpleAction(button, loadingText, path, payload, confirmText) {
        if (confirmText && !window.confirm(confirmText)) return Promise.resolve();
        return withButton(button, loadingText, function () {
            return apiWrite(path, payload || {}).then(function (data) {
                showFlash((data && (data.message || data.detail)) || '操作成功', 'ok', true);
                return data;
            });
        }).catch(function (error) {
            showFlash('操作失败：' + describeError(error), 'err', true);
        }).finally(function () {
            loadStatus();
            loadActions();
        });
    }

    /* ------------------------------------------------------------------ 状态轮询 */
    function applyStatus(status) {
        state.status = status;
        state.hasStatus = true;
        state.lastStatusAt = Date.now();

        dom.uptime.textContent = fmtUptime(status.uptime_s);
        var elevated = !!status.elevated;
        dom.adminBadge.setAttribute('data-level', elevated ? 'admin' : 'standard');
        dom.adminBadge.textContent = elevated ? '管理员模式' : '标准模式';
        dom.adminBadge.setAttribute('title', elevated ?
            '已获得管理员权限，可读取全部系统传感器' :
            '标准权限：部分传感器（如事件日志、Defender）可能需要管理员');

        renderStats(status);
        renderHost(status);
        renderSensors(status);
        updateSensorFilterOptions(state.sensors);
        renderExposure(status);

        if (state.settingsDrawerOpen && !state.settingsPopulated) {
            populateSettings();
        } else if (!state.settingsDrawerOpen && isObject(status.settings)) {
            state.settings = status.settings;
        }
    }

    function loadStatus() {
        if (state.polling.status) return Promise.resolve();
        if (document.hidden && state.hasStatus) return Promise.resolve();
        state.polling.status = true;
        return apiGet('/api/status').then(function (status) {
            setConnected(true);
            state.offlineRendered = false;
            applyStatus(isObject(status) ? status : {});
            dom.lastRefresh.textContent = fmtClock(Date.now() / 1000);
        }).catch(function () {
            setConnected(false);
            if (!state.hasStatus && !state.offlineRendered) {
                state.offlineRendered = true;
                renderInitialOffline();
            }
        }).finally(function () {
            state.polling.status = false;
        });
    }

    function loadActions() {
        if (document.hidden && state.hasStatus) return Promise.resolve();
        return apiGet('/api/actions/recent?limit=20').then(function (data) {
            renderActions(data && data.actions);
        }).catch(function () {
            if (!state.hasStatus) {
                dom.actionList.innerHTML = '<li class="panel-empty">未连接到哨兵服务</li>';
            }
        });
    }

    function renderInitialOffline() {
        if (state.hasStatus) return;
        dom.sensorList.innerHTML = panelEmpty('📡', '未连接', '等待本机哨兵服务启动后自动恢复');
        dom.sensorCount.textContent = '—';
        dom.sensorMeta.textContent = '—';
        dom.exposureList.innerHTML = panelEmpty('📡', '未连接', '等待本机哨兵服务启动后自动恢复');
        dom.exposureCount.textContent = '—';
        dom.exposureMeta.textContent = '—';
        dom.actionList.innerHTML = '<li class="panel-empty">未连接到哨兵服务</li>';
        dom.actionCount.textContent = '—';
        dom.overviewMeta.textContent = '统计窗口：最近 24 小时 · 等待连接';
        if (dom.chartSummary) dom.chartSummary.textContent = '等待连接本机哨兵服务…';
        if (dom.eventsCount) dom.eventsCount.textContent = '—';
        if (dom.pagerInfo) dom.pagerInfo.textContent = '—';
        dom.hostMeta.textContent = '—';
        dom.footerVersion.textContent = 'WHX Sentinel · 未连接';
        if (!state.eventsRenderedOnce) renderEventsUnavailable('等待本机哨兵服务启动后自动恢复…');
    }

    /* ------------------------------------------------------------------ 事件绑定 */
    function bindStaticEvents() {
        dom.btnSettings.addEventListener('click', function () {
            if (state.activeDrawer === dom.settingsDrawer) {
                closeDrawers();
            } else {
                openSettings(dom.btnSettings);
            }
        });
        dom.closeSettings.addEventListener('click', function () {
            closeDrawers();
        });
        dom.closeEventDrawer.addEventListener('click', function () {
            closeDrawers();
        });
        dom.drawerBackdrop.addEventListener('click', function () {
            closeDrawers();
        });
        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape' && state.activeDrawer) {
                event.preventDefault();
                closeDrawers();
            }
        });

        dom.btnSecurityCenter.addEventListener('click', function () {
            runSimpleAction(dom.btnSecurityCenter, '正在打开…', '/api/actions/open_security_center', {});
        });

        dom.eventsBody.addEventListener('click', function (event) {
            var row = event.target.closest('tr[data-id]');
            if (!row) return;
            openEvent(row.getAttribute('data-id'), row);
        });
        dom.eventsBody.addEventListener('keydown', function (event) {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            var row = event.target.closest('tr[data-id]');
            if (!row) return;
            event.preventDefault();
            openEvent(row.getAttribute('data-id'), row);
        });

        dom.filterSeverity.addEventListener('change', function () {
            state.filters.severity = dom.filterSeverity.value;
            state.offset = 0;
            loadEvents();
        });
        dom.filterSensor.addEventListener('change', function () {
            state.filters.sensor = dom.filterSensor.value;
            state.offset = 0;
            loadEvents();
        });
        dom.filterStatus.addEventListener('change', function () {
            state.filters.status = dom.filterStatus.value;
            state.offset = 0;
            loadEvents();
        });
        dom.filterQ.addEventListener('input', debounce(function () {
            state.filters.q = dom.filterQ.value.trim();
            state.offset = 0;
            loadEvents();
        }, 350));
        dom.btnClearFilters.addEventListener('click', function () {
            state.filters = { severity: '', sensor: '', status: '', q: '' };
            state.offset = 0;
            dom.filterSeverity.value = '';
            dom.filterSensor.value = '';
            dom.filterStatus.value = '';
            dom.filterQ.value = '';
            loadEvents();
        });
        dom.btnPrev.addEventListener('click', function () {
            state.offset = Math.max(0, state.offset - PAGE_SIZE);
            loadEvents();
        });
        dom.btnNext.addEventListener('click', function () {
            state.offset += PAGE_SIZE;
            loadEvents();
        });

        dom.actionList.addEventListener('click', function (event) {
            var item = event.target.closest('[data-event-id]');
            if (!item) return;
            openEvent(item.getAttribute('data-event-id'), item);
        });
        dom.actionList.addEventListener('keydown', function (event) {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            var item = event.target.closest('[data-event-id]');
            if (!item) return;
            event.preventDefault();
            openEvent(item.getAttribute('data-event-id'), item);
        });

        dom.eventFoot.addEventListener('click', handleEventActionClick);

        dom.canvas.addEventListener('mousemove', handleChartMove);
        dom.canvas.addEventListener('mouseleave', handleChartLeave);
        document.addEventListener('visibilitychange', function () {
            if (!document.hidden) {
                loadStatus();
                loadEvents();
                loadTimeline();
                loadActions();
            }
        });

        /* 设置：开关 */
        dom.setAiEnabled.addEventListener('change', function () {
            saveToggle(dom.setAiEnabled, 'ai_enabled', 'AI 研判');
        });
        dom.setToastEnabled.addEventListener('change', function () {
            saveToggle(dom.setToastEnabled, 'toast_enabled', 'Toast 通知');
        });
        dom.setAutoScan.addEventListener('change', function () {
            saveToggle(dom.setAutoScan, 'auto_quick_scan_on_malware', '自动快速扫描');
        });
        dom.setAutoBlock.addEventListener('change', function () {
            saveToggle(dom.setAutoBlock, 'auto_block_high_remote', '高危外联自动封锁');
        });
        dom.setCanary.addEventListener('change', function () {
            saveToggle(dom.setCanary, 'canary_enabled', '金丝雀文件监控');
        });
        dom.setToastSeverity.addEventListener('change', saveToastSeverity);
        dom.btnSaveAiModel.addEventListener('click', saveAiModel);
        dom.btnSaveRetention.addEventListener('click', saveRetention);
        dom.setAiModel.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                saveAiModel();
            }
        });

        dom.btnResetBaseline.addEventListener('click', function () {
            runSimpleAction(dom.btnResetBaseline, '重置中…', '/api/actions/reset_baseline', {},
                '确定要重置基线吗？\n自启动 / 文件完整性 / Defender 排除项将重新采集，已确认的基线状态会被清空。');
        });
        dom.btnTestToast.addEventListener('click', function () {
            runSimpleAction(dom.btnTestToast, '发送中…', '/api/actions/test_toast', {});
        });
        dom.btnShutdown.addEventListener('click', function () {
            if (!window.confirm('确定要停止 WHX 哨兵吗？\n停止后本机将不再被监控，看板会显示「未连接」；需要手动重新启动。')) return;
            withButton(dom.btnShutdown, '正在停止…', function () {
                return apiWrite('/api/actions/shutdown', {}).then(function (data) {
                    showFlash((data && (data.message || data.detail)) || '哨兵正在停止…', 'ok', true);
                });
            }).catch(function (error) {
                showFlash('停止哨兵失败：' + describeError(error), 'err', true);
            });
        });

        /* 白名单 */
        ALLOW_KINDS.forEach(function (kind) {
            var addButton = $('allow-add-' + kind);
            var input = $('allow-input-' + kind);
            if (addButton) {
                addButton.addEventListener('click', function () {
                    addAllowlistEntry(kind, addButton);
                });
            }
            if (input) {
                input.addEventListener('keydown', function (event) {
                    if (event.key === 'Enter') {
                        event.preventDefault();
                        addAllowlistEntry(kind, addButton);
                    }
                });
            }
        });
        dom.settingsDrawer.addEventListener('click', function (event) {
            var removeButton = event.target.closest('.chip-remove');
            if (!removeButton) return;
            var kind = removeButton.getAttribute('data-kind');
            var value = removeButton.getAttribute('data-value');
            if (!kind || value === null || ALLOW_KINDS.indexOf(kind) < 0) return;
            removeAllowlistEntry(kind, value);
        });
    }

    function bindChartResize() {
        if (typeof ResizeObserver === 'function' && dom.canvas && dom.canvas.parentElement) {
            var observer = new ResizeObserver(function () {
                drawChart();
            });
            observer.observe(dom.canvas.parentElement);
        }
        window.addEventListener('resize', debounce(resizeChart, 160));
    }

    /* ------------------------------------------------------------------ 启动 */
    function startPolling() {
        loadStatus();
        loadEvents();
        loadTimeline();
        loadActions();
        window.setInterval(loadStatus, POLL_STATUS_MS);
        window.setInterval(loadEvents, POLL_EVENTS_MS);
        window.setInterval(loadTimeline, POLL_TIMELINE_MS);
        window.setInterval(loadActions, POLL_ACTIONS_MS);
    }

    function init() {
        cacheDom();
        bindStaticEvents();
        bindChartResize();
        drawChart();
        startPolling();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
}());
