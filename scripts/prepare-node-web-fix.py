#!/usr/bin/env python3
"""Build a reversible, exact-image web-only overlay for the BE19000AI node."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STOCK = ROOT / 'build/stock-rootfs/www'
OUT = ROOT / 'build/node-web-fix'
OUT.mkdir(parents=True, exist_ok=True)
manifest = {'files': [], 'scope': 'Authenticated local node web UI; no network-role or authentication changes'}

def replace(text, old, new, count=1):
    assert text.count(old) == count, (old[:100], text.count(old), count)
    return text.replace(old, new)

def save(name, text):
    source = (STOCK / name).read_bytes()
    data = text.encode('utf-8')
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    manifest['files'].append({'path': name, 'source_sha256': hashlib.sha256(source).hexdigest(),
                              'patched_sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)})

def read(name):
    return (STOCK / name).read_text(encoding='utf-8')

# The AUTODICT hook reads Lang_Hdr.txt, whose stock non-ASCII labels were
# replaced with '?'. Reuse the intact UTF-8 labels shipped in Lang_Hdr while
# preserving the exact supported code set/order. HTTPD has a 30-byte buffer.
labels = dict(line.split('=', 1) for line in read('Lang_Hdr').splitlines()
              if line.startswith('LANG_') and '=' in line)
labels['LANG_RU'] = '\u0420усский'  # Correct the stock Latin P.
rows = read('Lang_Hdr.txt').splitlines()
assert len(rows) == 25 and all(line.startswith('LANG_') for line in rows)
fixed_rows = []
for line in rows:
    key, _ = line.split('=', 1)
    label = labels[key]
    assert '?' not in label and len(label.encode('utf-8')) < 30
    fixed_rows.append(key + '=' + label)
save('Lang_Hdr.txt', '\n'.join(fixed_rows) + '\n')

s = read('index.html')
s = replace(s, 'function checkPolicy() {', '''function checkPolicy() {
// Match the existing state.js node behavior; consent records and feature-specific
// agreement flows are unchanged. A node receives the controller's base settings.
if (httpApi.nvramGet(["re_mode"]).re_mode === "1") return;''')
save('index.html', s)

s = read('js/basic.js')
s = replace(s, 'src="images/merlin-logo-dark.png"', 'src="${document.documentElement.getAttribute(\'data-asuswrt-color\') === \'dark\' ? \'images/merlin-logo.png\' : \'images/merlin-logo-dark.png\'}"')
s = replace(s, 'function genNavMenu() {', '''// AI-board services are local to the board, including in AP/AiMesh node mode.
if (isSupport("ai_support") && !menuList.some(item => item.url === "aiboard")) {
const settingsIndex = menuList.findIndex(item => item.url === "settings");
menuList.splice(settingsIndex < 0 ? menuList.length : settingsIndex, 0, {
name: "AI Board / Docker", icon: "icon-AiBoard", url: "aiboard", clicked: false, divide: false
});
}
function genNavMenu() {''')
s = replace(s, "htmlElement.setAttribute('data-asuswrt-color', buttonValue);", """htmlElement.setAttribute('data-asuswrt-color', buttonValue);
const merlinLogo = header.querySelector('a[href="https://www.asuswrt-merlin.net/"] img');
if (merlinLogo) merlinLogo.src = buttonValue === 'dark' ? 'images/merlin-logo.png' : 'images/merlin-logo-dark.png';""")
save('js/basic.js', s)

s = read('state.js')
pos = s.index('var pathSegments =')
s = '''\ufeff// Keep UI4 standalone pages and embedded pages on the same theme.
(function () {
const html = document.documentElement;
if (!isSupport("UI4")) html.setAttribute("data-asuswrt-color", "dark");
else if (window.self === window.top) {
const prefs = typeof httpApi !== "undefined" ? httpApi.nvramGet(["productid", "ui_color_mode", "ui_theme", "ui_style"]) : {productid: "GT-BE19000AI"};
let savedColor = "", savedStyle = "";
try { savedColor = localStorage.getItem("theme-mode-preference"); savedStyle = localStorage.getItem("theme-style-preference"); } catch (_) {}
const defaultColor = prefs.productid === "GT-BE19000AI" || prefs.productid === "GT-BE96_AI" ? "light" : "dark";
html.setAttribute("data-asuswrt-color", ["dark", "light"].includes(savedColor) ? savedColor : (["dark", "light"].includes(prefs.ui_color_mode) ? prefs.ui_color_mode : defaultColor));
html.setAttribute("data-asuswrt-theme", prefs.ui_theme || (isSupport("rog") ? "rog" : isSupport("tuf") ? "tuf" : "asus"));
html.setAttribute("data-asuswrt-style", savedStyle === "fancy" ? "tech" : savedStyle === "normal" ? "" : (prefs.ui_style || ""));
}
if (window.self !== window.top) {
try {
["color", "theme", "style"].forEach(key => {
const value = top.document.documentElement.getAttribute("data-asuswrt-" + key);
if (value !== null) html.setAttribute("data-asuswrt-" + key, value);
});
} catch (_) {}
window.addEventListener("message", event => {
if (event.origin !== location.origin || !event.data) return;
["color", "theme", "style"].forEach(key => {
if (typeof event.data[key] === "string") html.setAttribute("data-asuswrt-" + key, event.data[key]);
});
});
}
})();
''' + s[pos:]
save('state.js', s)

s = read('SDN/sdn.html')
s = replace(s, '<script type="text/javascript" src="../calendar/jquery-ui.js" defer></script>\n', '')
s = replace(s, '<script type="text/javascript" src="../state.js"></script>', '<script type="text/javascript" src="../calendar/jquery-ui.js"></script>\n<script type="text/javascript" src="../state.js"></script>')
save('SDN/sdn.html', s)

s = read('css/architecture.css')
s += '''
/* Readable text on the dark ROG surfaces, preserving the selected theme. */
html[data-asuswrt-color="dark"] {
  --text-secondary: #c4c9d2;
  --text-muted: #aeb5c1;
  --wrt-card-title-color: #ff8694;
  --text-card-title-color: #ff8694;
  --wrt-input-placeholder: #b8c0cc;
}
html[data-asuswrt-color="dark"] .card-header { color: #ff8694; }
html[data-asuswrt-color="dark"] .setting-info,
html[data-asuswrt-color="dark"] .card-description,
html[data-asuswrt-color="dark"] .safe-description { color: #cbd1da; }
body { font-size: .875rem; }
'''
save('css/architecture.css', s)

s = read('pages/aiboard.html')
s = replace(s, '<div class="card-footer text-end d-none">', '<div class="card-footer text-end">')
s = replace(s, '<div id="ai_hostname_postfix" class="setting-info">.local</div>', '''<div id="ai_hostname_postfix" class="setting-info">.local</div>
<div id="hint_ai_hostname" class="setting-info" role="status" aria-live="polite"></div>''')
s = replace(s, 'maxlength="32"', 'maxlength="32" minlength="5" aria-describedby="ai_hostname_postfix hint_ai_hostname"')
# Replace the legacy broad form handler; enable only after the initial read.
start = s.index('const ApplyBtn = document.getElementById("applyBtn");')
end = s.index('\n});\nif (ai_fw_path_str', start)
assert 'postObject.ai_portainer_enable' in s[start:end]
s = s[:start] + (ROOT/'configs/node-web-fix/ai-hostname.js').read_text() + '\ninstallAiHostnameEditor();' + s[end:]

s = replace(s, '</style>', '''/* The stock translucent white app cards lose contrast in dark mode. */
html[data-asuswrt-color="dark"] .safe-item {
background: #24262e;
border-color: #646c7c;
}
html[data-asuswrt-color="dark"] .safe-item .safe-title { color: #f4f6fa; }
html[data-asuswrt-color="dark"] .safe-item .safe-description { color: #d5dbe6; }
html[data-asuswrt-color="dark"] .safe-label { color: #ffa9b4; font-size: 14px; }
html[data-asuswrt-color="dark"] .safe-item .btn-outline-primary,
html[data-asuswrt-color="dark"] #card_portainer .btn-outline-primary,
html[data-asuswrt-color="dark"] .app-card .btn-outline-primary {
color: #ffa9b4 !important;
border-color: #ffa9b4 !important;
--bs-btn-color: #ffa9b4;
--bs-btn-border-color: #ffa9b4;
--bs-btn-hover-color: #14161c;
--bs-btn-hover-bg: #ffa9b4;
--bs-btn-hover-border-color: #ffa9b4;
--bs-btn-disabled-color: #d9aeb7;
--bs-btn-disabled-border-color: #9e7f87;
}
html[data-asuswrt-color="dark"] :is(.safe-item, #card_portainer, .app-card) .btn-outline-primary:not(.disabled):not(:disabled):hover {
color: #14161c !important;
background-color: #ffa9b4 !important;
}
</style>''')

s = replace(s, 'const ai_hostname_str = httpApi.nvramGet(["ai_hostname"]).ai_hostname;', '''const board = httpApi.nvramGet(["ai_hostname", "ai_sys_ip_address"], true);
const octets = String(board.ai_sys_ip_address || "").split(".");
const validIP = octets.length === 4 && octets.every(v => /^\\d{1,3}$/.test(v) && Number(v) <= 255);
const ai_hostname_str = board.ai_hostname;
const ai_host = validIP ? board.ai_sys_ip_address : `${ai_hostname_str}.local`;''')
s = s.replace('${ai_hostname_str}.local:', '${ai_host}:')
s = replace(s, 'return await httpApi.get_ai_docker_container();', '''const response = await fetch('/get_ai_docker_container.cgi', {cache: 'no-store'});
if (!response.ok) throw new Error('AI Board status unavailable');
const data = await response.json();
if (!Array.isArray(data)) throw new Error('Invalid AI Board container status');
return data;''')
s = replace(s, '});\nlet dead = 0;', '''}).catch(error => {
statusInfo.textContent = '容器狀態暫時無法讀取';
const message = document.createElement('div');
message.className = 'alert alert-warning';
message.setAttribute('role', 'status');
message.textContent = 'AI Board 容器狀態暫時無法讀取，請稍後重新整理。';
document.querySelector('#card_portainer')?.prepend(message);
document.querySelectorAll('.app-install-btn, .app-open-btn').forEach(button => { button.classList.add('disabled'); button.setAttribute('aria-disabled', 'true'); });
console.warn('AI Board status:', error.message);
});
let dead = 0;''')

s = replace(s, 'const get_ai_docker_date = async () => {', """const statusInfo = document.createElement('div');
statusInfo.className = 'setting-info';
statusInfo.id = 'node_ai_container_status';
statusInfo.textContent = '正在讀取容器狀態…';
document.getElementById('ai_hostname').closest('section').appendChild(statusInfo);
const boardAddress = document.createElement('div');
boardAddress.className = 'setting-info';
boardAddress.textContent = 'AI Board IP: ' + (httpApi.nvramGet(['ai_sys_ip_address'], true).ai_sys_ip_address || '尚未取得');
statusInfo.before(boardAddress);
const get_ai_docker_date = async () => {""")
s = replace(s, 'get_ai_docker_date().then(async data => {', """get_ai_docker_date().then(async data => {
statusInfo.textContent = data.length ? '容器狀態' : '目前沒有容器';
const list = document.createElement('ul');
for (const container of data) {
const item = document.createElement('li');
item.textContent = String(container.name || '') + ' — ' + String(container.status || '未知');
list.appendChild(item);
}
statusInfo.appendChild(list);""")
save('pages/aiboard.html', s)

# Node SDN profiles are owned by the controller. Show the real wireless status
# instead of a blank editor that could apply empty/default local profiles.
s = read('pages/sdn.html')
s = replace(s, 'var webWrapper = true;', """var webWrapper = true;
// Legacy status pages expect the wrapper to reveal and fit their document.
window.setupBusinessUI = function () {
const frame = $('#settingsWindow').contents();
frame.find('body').css({visibility: 'visible', background: 'transparent'}).addClass('scaleBody');
frame.find('#TopBanner, #mainMenu, #subMenu, #footer, .bg-shadow-right').hide();
frame.find('#FormTitle').attr('width', '100%');
frame.find('#FormTitle').parent().parent().parent().attr('width', '100%');
frame.find('td[width="202"], td[width="17"], td[width="20"]').hide();
};""")

s = replace(s, '.attr({src: `${rootPath}/SDN/sdn.html?current_theme=${theme}`})', '''.attr({src: (() => {
const role = httpApi.nvramGet(["re_mode", "cfg_masterip"]);
if (role.re_mode !== "1") return `${rootPath}/SDN/sdn.html?current_theme=${theme}`;
document.querySelector('.page-title').textContent = '無線狀態（AiMesh 節點）';
const notice = document.createElement('div');
notice.className = 'alert alert-info';
notice.textContent = 'Wi-Fi 設定由主節點同步；此處顯示本機無線狀態。系統、AI Board 與 Docker 可在本機管理。 ';
const ip = String(role.cfg_masterip || "");
if (/^\\d{1,3}(\\.\\d{1,3}){3}$/.test(ip) && ip.split('.').every(v => Number(v) <= 255)) {
const link = document.createElement('a');
link.textContent = '開啟主節點 Wi-Fi 設定';
link.href = `${location.protocol}//${ip}${location.port ? ':' + location.port : ''}/Advanced_Wireless_Content.asp`;
link.target = '_blank'; link.rel = 'noopener';
notice.appendChild(link);
}
document.getElementById('settingsWindow').before(notice);
return `${rootPath}/Main_WStatus_Content.asp`;
})()})''')
save('pages/sdn.html', s)

# Use the existing raw query branch. Zero/zero is libcodb's documented last-24h convention.
s = read('js/dashboard.module.js')
s = replace(s, 'export class WiFiInterferenceChart {', '''async function fetchLegacyDiagnosticRange(queryString) {
const requested = new URLSearchParams(queryString);
const start=Number(requested.get('starttime')),end=Number(requested.get('endtime'));
const fields=(requested.get('content')||'').split(';'),timeIndex=fields.indexOf('data_time');
if(timeIndex<0||!Number.isFinite(start)||!Number.isFinite(end)||end<start) throw new Error('Invalid diagnostic range');
requested.delete('starttime');requested.delete('endtime');
requested.set('ts','0');requested.set('duration','0');requested.set('point','0');requested.set('limit','5000');requested.set('order_by','DESC');
const response=await fetch('/get_diag_content_data.cgi?'+requested,{cache:'no-store',signal:AbortSignal.timeout(10000)});
if(!response.ok)throw new Error('Diagnostic query failed');
const data=await response.json();
if(!Array.isArray(data.contents))throw new Error('Invalid diagnostic response');
data.contents=data.contents.filter(row=>Number(row[timeIndex])>=start&&Number(row[timeIndex])<=end).sort((a,b)=>Number(a[timeIndex])-Number(b[timeIndex]));
return new Response(JSON.stringify(data), {headers: {'Content-Type': 'application/json'}});
}
export class WiFiInterferenceChart {''')
import re
s, n = re.subn(r'fetch\(`/get_diag_raw_data\.cgi\?\$\{(\w+)\}`\)', r'fetchLegacyDiagnosticRange(\1)', s)
assert n == 4, n
save('js/dashboard.module.js', s)

s = read('pages/dashboard.html')
# Keep the main router separate from local ASUS node telemetry.
s = s.replace('<div class="row">', '<div class="row">\n<div class="col-12 mb-3"><section id="networkOverview" class="card pt-2" aria-label="Network overview"></section></div><div class="col-12 mb-3"><section id="ccrStatus" class="card pt-2" aria-label="CCR2216"></section></div>', 1)
# Replace the legacy iframe and its orphaned legend on this exact node overlay.
port_start = s.rindex('<div class="col-12 col-md-6 col-xl-4 mb-3">', 0, s.index('id="ethPortStatus"'))
port_end = s.index('<div id="aura_rgb_field"', port_start)
s = s[:port_start] + '''<div class="col-12 col-md-6 col-xl-4 mb-3">
<div class="card pt-2 h-100">
<h5 class="card-header"><#Status_Ethernet_Ports#></h5>
<div id="nodeEthernetStatus" class="card-body p-0"></div>
</div>
</div>
''' + s[port_end:]

s = replace(s, 'wifiInterferenceView.append(wifiInterferenceChart.render());', """const note = document.createElement('div');
note.className = 'alert alert-info';
note.textContent = '歷史圖表僅顯示收集器實際保存的記錄；空資料不代表沒有干擾。';
wifiInterferenceView.append(note, wifiInterferenceChart.render());""")

start = s.index('httpApi.get_diag_content_data(\n{')
end = s.index('httpApi.get_diag_eth_traffic_data(', start)
old = s[start:end]
old = replace(old, 'for (let item of e.contents)', 'for (let item of (e.contents || []))')
old = replace(old, 'genCpuRam([cpuData, ramData]);', '''if (cpuData.some(value => value !== null && value !== '' && Number.isFinite(Number(value)))) genCpuRam([cpuData, ramData]);
else startNodeLiveCpuRam();''')
s = s[:start] + '''if (httpApi.nvramGet(["re_mode"]).re_mode === "1") startNodeLiveCpuRam();
else {
''' + old + '}\n' + s[end:]
live = r'''
function startNodeLiveCpuRam() {
const canvas = document.getElementById('cpu_ram_chart');
if (!canvas || canvas.dataset.liveTelemetry) return;
canvas.dataset.liveTelemetry = '1';
let previous = null, chart = null;
const cpuElement = document.getElementById('cpu_usage_value');
const ramElement = document.getElementById('ram_usage_value');
cpuElement.textContent = '—'; ramElement.textContent = '—';
canvas.closest('.card').querySelector('.card-header').textContent = '系統資訊（本機即時）';
async function sample() {
if (!canvas.isConnected) { if (chart) chart.destroy(); return; }
try {
const response = await fetch('/cpu_ram_status.asp', {cache: 'no-store', signal: AbortSignal.timeout(4000)});
if (!response.ok) throw new Error('CPU/RAM status unavailable');
const text = await response.text();
function readAssignment(name) {
const marker = name + ' =';
const offset = text.lastIndexOf(marker);
const end = text.indexOf(';', offset);
if (offset < 0 || end < 0) throw new Error('Invalid CPU/RAM status');
return JSON.parse(text.slice(offset + marker.length, end).trim());
}
const cores = Object.values(readAssignment('cpuInfo'));
const memory = readAssignment('memInfo');
const current = cores.reduce((a, c) => ({total: a.total + Number(c.total), usage: a.usage + Number(c.usage)}), {total: 0, usage: 0});
const totalDelta = previous ? current.total - previous.total : 0;
const usageDelta = previous ? current.usage - previous.usage : 0;
const cpu = totalDelta > 0 && usageDelta >= 0 ? Math.min(100, Math.max(0, 100 * usageDelta / totalDelta)) : null;
const ram = Number(memory.total) > 0 ? 100 * Number(memory.simple_used) / Number(memory.total) : null;
previous = current;
if (!canvas.isConnected) return;
cpuElement.textContent = cpu === null ? '—' : cpu.toFixed(1) + ' %';
ramElement.textContent = ram === null || !Number.isFinite(ram) ? '—' : ram.toFixed(1) + ' %';
if (!chart) {
const oldChart = Chart.getChart(canvas); if (oldChart) oldChart.destroy();
const css = getComputedStyle(document.documentElement);
chart = new Chart(canvas, {type: 'line', data: {labels: [], datasets: [
{label: 'CPU', data: [], borderColor: css.getPropertyValue('--chart-color-1').trim(), spanGaps: false},
{label: 'RAM', data: [], borderColor: css.getPropertyValue('--chart-color-2').trim(), spanGaps: false}
]}, options: {responsive: true, maintainAspectRatio: false, animation: false,
plugins: {legend: {display: false}}, scales: {
y: {min: 0, max: 100, ticks: {color: css.getPropertyValue('--text-regular-color'), callback: value => value + ' %'}},
x: {ticks: {maxTicksLimit: 5, color: css.getPropertyValue('--text-regular-color')}}}}});
}
chart.data.labels.push(new Date().toLocaleTimeString());
chart.data.datasets[0].data.push(cpu); chart.data.datasets[1].data.push(Number.isFinite(ram) ? ram : null);
if (chart.data.labels.length > 30) { chart.data.labels.shift(); chart.data.datasets.forEach(d => d.data.shift()); }
chart.update('none');
} catch (error) {
if (canvas.isConnected) { cpuElement.textContent = '—'; ramElement.textContent = '—'; }
previous = null;
console.warn('Live CPU/RAM:', error.message);
}
if (canvas.isConnected) setTimeout(sample, 5000);
}
sample();
}
'''
s = replace(s, 'function genCpuRam(rawData) {', live + '\nfunction genCpuRam(rawData) {')
# Local nodes use their own measured history, without controller-owned empty arrays.
start = s.index('httpApi.get_diag_eth_traffic_data(')
end = s.index('setTimeout(genCustomCard, 1000);', start)
s = s[:start] + 'if (httpApi.nvramGet(["re_mode"]).re_mode === "1") startNodeHistory();\nelse {\n' + s[start:end] + '}\n' + s[end:]
s = replace(s, 'function genAllClient() {', (ROOT/'configs/node-web-fix/node-history.js').read_text() + '\nfunction genAllClient() {')
s = replace(s, 'function genAllClient() {', (ROOT/'configs/node-web-fix/wireless-snapshot.js').read_text() + '\n' + (ROOT/'configs/node-web-fix/node-insight.js').read_text() + '\n' + (ROOT/'configs/node-web-fix/dashboard-clients.js').read_text() + '\nfunction genAllClient() {\nif (httpApi.nvramGet(["re_mode"]).re_mode === "1") { startNodeWirelessClients(); return; }')
s = replace(s, 'system.client = updateSystemClient({ forceUpdate: true });', 'if (httpApi.nvramGet(["re_mode"]).re_mode !== "1") system.client = updateSystemClient({ forceUpdate: true });')
s = replace(s, 'const wifiInterferenceChart = new WiFiInterferenceChart(system.labelMac);', 'const wifiInterferenceChart = httpApi.nvramGet(["re_mode"]).re_mode === "1" ? null : new WiFiInterferenceChart(system.labelMac);')
s = replace(s, 'if (wifiInterferenceView) {', 'if (wifiInterferenceView && wifiInterferenceChart) {')
s = replace(s, 'function genAllClient() {', (ROOT/'configs/node-web-fix/node-ethernet.js').read_text() + '\nfunction genAllClient() {\nstartNodeEthernet();')
s = replace(s, 'function genAllClient() {', (ROOT/'configs/node-web-fix/network-overview.js').read_text() + '\n' + (ROOT/'configs/node-web-fix/ccr-status.js').read_text() + '\nfunction genAllClient() {\nstartCcrStatus();')
save('pages/dashboard.html', s)

s = read('pages/trafficmonitor.html')
s = replace(s, 'var inspect_length = 120,', (ROOT/'configs/node-web-fix/node-history.js').read_text() + '\nvar inspect_length = 120,')
s = replace(s, 'function getTraffic() {', 'function getTraffic() {\nif (httpApi.nvramGet(["re_mode"]).re_mode === "1") return;')
s = replace(s, 'function genIfElement() {', """function genIfElement() {
if (httpApi.nvramGet(["re_mode"]).re_mode === "1") {
const field=document.getElementById('if_card_field');
const card=document.createElement('div');card.className='card';
const canvas=document.createElement('canvas');canvas.id='bw_chart';card.appendChild(canvas);field.replaceChildren(card);
startNodeHistory();return;
}""")
save('pages/trafficmonitor.html', s)

for page, condition in [('Advanced_SwitchCtrl_Content.asp', 'if (re_mode == "1"){'), ('APP_Installation.asp', 'if(re_mode == "1"){')]:
    s = read(page)
    suffix = '\n$("#FormTitle").addClass("perNode_app_table");' if page == 'APP_Installation.asp' else ''
    s = replace(s, condition + suffix, 'if (re_mode == "1" && !isWebWrapper){' + suffix)
    save(page, s)

s = read('Advanced_OperationMode_Content.asp')
s = replace(s, 'var current_page =', '// Actual AiMesh membership takes precedence over the legacy repeater label.\nif (re_mode === "1") sw_mode_orig = 5;\nvar current_page =')
s = replace(s, 'show_menu();', '''show_menu();
if (re_mode === "1") {
const roleNote = document.createElement('p');
roleNote.id = 'node_operation_mode_note';
roleNote.textContent = '目前為 AiMesh 節點，本機管理與有線回程可以並存。' + ((!repeater_support && !psta_support) ? ' 這版韌體未提供獨立中繼器與媒體橋接的模式選項。' : '');
document.getElementById('operation_mode_bg').before(roleNote);
}''')
save('Advanced_OperationMode_Content.asp', s)

s = read('Main_WStatus_Content.asp')
s = replace(s, 'var content = "";', (ROOT/'configs/node-web-fix/wireless-snapshot.js').read_text() + '\nvar nodeWirelessSnapshot = null;\nvar content = "";')
s = replace(s, 'function Get_wireless_log(){', '''function Get_wireless_log(){
if (re_mode === "1" && nodeWirelessSnapshot) {
document.getElementById('wl_log').value = nodeWirelessSnapshot.detail;
return;
}''')
s = replace(s, 'function get_wlclient_list() {', '''function get_wlclient_list() {
if (re_mode === "1") {
if (timedEvent) clearTimeout(timedEvent);
fetch('/ajax_wificlients.asp', {cache:'no-store', signal:AbortSignal.timeout(5000)})
.then(response => {if (!response.ok) throw new Error('Wireless status unavailable');return response.text();})
.then(text => {
nodeWirelessSnapshot = parseNodeWirelessSnapshot(text);
const headers = nodeWirelessSnapshot.radios.map(r => r.live ? [r.live.ssid,0,0,r.live.noise === null ? '?' : r.live.noise,r.live.channel,r.live.bssid,r.live.utilization === null ? -1 : r.live.utilization,'AP'] : (r.header.length >= 8 ? r.header : ['狀態未提供',0,0,0,'—','—',-1,'—']));
[dataarray0,dataarray1,dataarray2] = headers;
[wificlients0,wificlients1,wificlients2] = nodeWirelessSnapshot.radios.map(r => r.clients.concat(['-1']));
[dfs_statusarray0,dfs_statusarray1,dfs_statusarray2] = nodeWirelessSnapshot.radios.map(r => r.dfs);
redraw();
}).catch(error => {
nodeWirelessSnapshot = null;
document.getElementById('datablock').textContent = '無線資料暫時無法取得；未顯示過期裝置資料。';
document.getElementById('wl_log').value = '';
console.warn('Node wireless log:',error.message);
}).finally(() => {if(refreshRate > 0) timedEvent=setTimeout(get_wlclient_list,refreshRate*1000);});
return;
}''')
s = replace(s, 'code += generate_clients(client_array[i]);', '''if (re_mode === "1") {
const links = client_array[i].filter(c => Array.isArray(c) && String(c[11]).includes('A') && String(c[11]).includes('U'));
code += '<p>本機已授權連線：' + new Set(links.map(c=>c[0])).size + '（MLO 各頻段可能屬於同一台裝置）</p>';
}
code += generate_clients(client_array[i]);''')
s = replace(s, 'var guestBackgroundColor = "background-color: #EEEEEE;";', 'var guestBackgroundColor = document.documentElement.getAttribute("data-asuswrt-color") === "dark" ? "background-color: #24262e;" : "background-color: #EEEEEE;";')
s = replace(s, 'if (nmapentry && ipaddr == "<unknown>") {', 'if (nmapentry && (ipaddr == "<unknown>" || ipaddr === "")) {')
s = replace(s, '+ dataarray[0] +', '+ htmlEnDeCode.htmlEncode(String(dataarray[0] || "—")) +')
s = replace(s, 'code +=`<br><span class="amng-secondary-color" class="amng-secondary-color" style="margin-top:-15px;"${hostname}">${hostname.substring(0,20)}...</span></td>`;', 'code += `<br><span class="amng-secondary-color" style="margin-top:-15px;">${htmlEnDeCode.htmlEncode(hostname.substring(0,20))}...</span></td>`;')
s = replace(s, 'Guest Network: </span> ', 'SSID: </span> ')
save('Main_WStatus_Content.asp', s)


(OUT/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
print(json.dumps({'files': len(manifest['files']), 'output': str(OUT)}, indent=2))
