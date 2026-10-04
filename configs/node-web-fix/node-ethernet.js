// Model-scoped local physical-port view; no controller SHM dependency and no
// eval of the legacy JavaScript endpoint. Labels match GTBE19000AI PHY mapping.
function parseNodeEthernetStatus(data) {
    const speeds = data && data.portSpeed;
    if (!speeds || typeof speeds !== 'object' || Array.isArray(speeds)) throw new Error('No port status');
    const ports = [
        ['WAN 0', 'WAN / LAN', '10 Gbps'],
        ['LAN 1', 'LAN 1', '2.5 Gbps'], ['LAN 2', 'LAN 2', '2.5 Gbps'],
        ['LAN 3', 'LAN 3', '2.5 Gbps'], ['LAN 4', 'LAN 4', '2.5 Gbps'],
        ['LAN 5', 'LAN 5', '1 Gbps'], ['LAN 6', 'LAN 6', '10 Gbps']
    ];
    if (!ports.some(([key]) => Object.prototype.hasOwnProperty.call(speeds, key))) throw new Error('Empty port status');
    const rates = {t:'10 Mbps',M:'100 Mbps',G:'1 Gbps',Q:'2.5 Gbps',F:'5 Gbps',T:'10 Gbps'};
    return ports.map(([key, label, capacity]) => {
        const code = speeds[key];
        const knownRate = typeof code === 'string' && Object.prototype.hasOwnProperty.call(rates, code);
        return {key, label, capacity, state:code === 'X' ? 'down' : knownRate ? 'up' : 'unknown', rate:knownRate ? rates[code] : null};
    });
}
function startNodeEthernet() {
    const root = document.getElementById('nodeEthernetStatus');
    if (!root || root.dataset.started) return;
    root.dataset.started = '1';
    const tw = system.language.currentLang === 'TW';
    const msg = (zh,en) => tw ? zh : en;
    const status = document.createElement('div');
    status.className = 'setting-info px-3 pt-2'; status.setAttribute('role','status');
    const table = document.createElement('table');
    table.className = 'table align-middle mb-2';
    table.setAttribute('aria-label',msg('本機乙太網路連接埠','Local Ethernet ports'));
    const head = table.createTHead().insertRow();
    for (const text of [msg('連接埠','Port'),msg('連線狀態','Link status')]) {
        const th = document.createElement('th'); th.scope='col'; th.textContent=text; head.appendChild(th);
    }
    const body = table.createTBody();
    const holder = document.createElement('div');holder.className='table-responsive px-3';holder.appendChild(table);
    const note = document.createElement('p');note.className='setting-info px-3 mb-2';
    note.textContent=msg('顯示目前協商速率；聚合成員埠分別列出。較低速率也可能是對端設備的正常限制。',
                         'Current negotiated rates; aggregation members are shown separately. Lower rates can reflect the peer device’s limits.');
    root.replaceChildren(status,holder,note);
    const render = ports => {
        body.replaceChildren();
        for (const port of ports) {
            const row=body.insertRow(),name=row.insertCell(),link=row.insertCell();
            name.textContent=port.label;
            const capacity=document.createElement('small');capacity.className='d-block setting-info';
            capacity.textContent=msg('最高 ','Up to ')+port.capacity;name.appendChild(capacity);
            const dot=document.createElement('span');dot.setAttribute('aria-hidden','true');
            dot.style.cssText='display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px;background:'+(port.state==='up'?'#36bc88':port.state==='down'?'#88909c':'#e6b85c');
            link.appendChild(dot);
            link.appendChild(document.createTextNode(port.state==='up' ? port.rate : port.state==='down' ? msg('未連線','Disconnected') : msg('狀態未知','Unknown')));
        }
    };
    async function refresh() {
        if (!root.isConnected) return;
        try {
            const response=await fetch('/appGet.cgi?hook=get_wan_lan_status()',{cache:'no-store',signal:AbortSignal.timeout(5000)});
            if (!response.ok) throw new Error('Port query failed');
            const data=await response.json(),ports=parseNodeEthernetStatus(data.get_wan_lan_status);
            if (!root.isConnected) return;
            render(ports);
            status.textContent=msg('已連線 ','Connected ')+ports.filter(p=>p.state==='up').length+'/7 · '+new Date().toLocaleTimeString();
        } catch (_) {
            if (!root.isConnected) return;
            render(parseNodeEthernetStatus({portSpeed:{'WAN 0':null}}));
            status.textContent=msg('暫時無法讀取埠狀態；未保留過期讀數。','Port status unavailable; old readings have been cleared.');
        } finally {
            if (root.isConnected) setTimeout(refresh,5000);
        }
    }
    status.textContent=msg('正在讀取本機連接埠…','Reading local ports…');
    refresh();
}
