// The browser reads only the ASUS authenticated API, never RouterOS credentials.
function parseCcrStatus(response) {
    if (!response || !Array.isArray(response.contents) || response.contents.length !== 1) throw new Error('No CCR snapshot');
    const row=response.contents[0];
    if (!Array.isArray(row) || row.length !== 2 || typeof row[1] !== 'string' || row[1].length > 180000) throw new Error('Invalid CCR snapshot');
    const bytes=Uint8Array.from(atob(row[1]),c=>c.charCodeAt(0));
    const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    if (data.schema !== 1 || data.ip !== '192.168.100.1' || !['ok','partial','unavailable'].includes(data.status)) throw new Error('Wrong CCR snapshot');
    if (data.status !== 'unavailable' && (!Array.isArray(data.ports) || !Array.isArray(data.health) || !String(data.model).startsWith('CCR2216'))) throw new Error('Incomplete CCR snapshot');
    return data;
}
function ccrSnapshotFresh(data,now) {
    const age=now-Number(data.seen);
    return data.status !== 'unavailable' && Number(data.seen)>0 && Number.isFinite(age) && age>=-10 && age<=90;
}
function ccrPhysicalGroups(ports) {
    const groups=[];
    for(const p of ports) {
        const match=/^qsfp28-([12])-[1-4]$/.exec(p.physical);
        const key=match?'qsfp28-'+match[1]:p.physical;
        let group=groups.find(g=>g.key===key);
        if(!group){group={key,ports:[]};groups.push(group);}
        group.ports.push(p);
    }
    return groups;
}
function startCcrStatus() {
    const root=document.getElementById('ccrStatus');
    if(!root || root.dataset.started)return;
    root.dataset.started='1';
    const tw=system.language.currentLang==='TW',msg=(zh,en)=>tw?zh:en;
    function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
    const header=el('div',undefined,'d-flex flex-wrap align-items-center justify-content-between gap-2');
    const title=el('h5',msg('主路由器｜CCR2216','Main router | CCR2216'),'card-header mb-0');
    const link=el('a',msg('開啟 RouterOS','Open RouterOS'),'btn btn-outline-primary btn-sm me-3');
    link.href='http://192.168.100.1/';link.target='_blank';link.rel='noopener noreferrer';
    header.append(title,link);
    const body=el('div',undefined,'card-body');
    const status=el('div',msg('正在讀取 CCR2216…','Reading CCR2216…'),'mb-2 fw-bold');
    status.id='ccrStatusMessage';status.setAttribute('role','status');
    const subtitle=el('div','','setting-info mb-3');
    const metrics=el('div');metrics.id='ccrMetrics';metrics.style.cssText='display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px';
    const health=el('div',undefined,'d-flex flex-wrap gap-2 mb-3');health.id='ccrHealth';
    const portTitle=el('h6',msg('實體連接埠','Physical ports'));
    const ports=el('div');ports.id='ccrPorts';ports.style.cssText='display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px';
    const details=el('details',undefined,'mt-3');details.appendChild(el('summary',msg('介面流量與錯誤計數','Interface traffic and error counters')));
    const holder=el('div',undefined,'table-responsive');const table=el('table',undefined,'table align-middle mt-2');
    table.setAttribute('aria-label',msg('CCR2216 介面流量','CCR2216 interface traffic'));
    const tr=table.createTHead().insertRow();
    [msg('介面','Interface'),msg('協商速率','Link rate'),msg('接收','Receive'),msg('送出','Transmit'),msg('錯誤 RX / TX','Errors RX / TX'),msg('丟棄 RX / TX','Drops RX / TX')].forEach(text=>{const th=el('th',text);th.scope='col';tr.appendChild(th);});
    const rows=table.createTBody();holder.appendChild(table);details.appendChild(holder);
    const note=el('p',msg('由 BE19000AI 直接讀取 CCR2216，約每 30 秒更新。流量方向以 CCR2216 為準；QSFP28 的分拆通道歸在同一個實體插槽，完整介面列於下方。','Read directly from CCR2216 by BE19000AI, approximately every 30 seconds. Traffic direction is relative to CCR2216. QSFP28 breakout lanes share one physical cage; all interfaces are listed below.'),'setting-info mt-3 mb-0');
    body.append(status,subtitle,metrics,health,portTitle,ports,details,note);root.replaceChildren(header,body);
    const valid=n=>typeof n==='number' && Number.isFinite(n) && n>=0;
    const number=(n,unit='')=>valid(n)?n.toLocaleString(undefined,{maximumFractionDigits:1})+unit:'—';
    const traffic=n=>!valid(n)?msg('等待採樣','Awaiting sample'):n>=1000?(n/1000).toFixed(2)+' Gbps':n.toFixed(2)+' Mbps';
    function metric(label,value){const card=el('div',undefined,'border rounded p-2');card.append(el('div',label,'setting-info'),el('div',value,'fs-5 fw-bold'));metrics.appendChild(card);}
    const overview=createNetworkOverview();
    let last=null;
    function render(data) {
        const fresh=ccrSnapshotFresh(data,Date.now()/1000);
        overview.update(data,fresh);
        status.textContent=fresh?(data.status==='partial'?msg('部分資料暫時無法取得','Some data is unavailable'):msg('資料正常','Status available')):msg('資料已過期或無法連線；下方即時讀數已清除','Data is stale or unavailable; live readings cleared');
        status.dataset.state=fresh?data.status:'stale';
        status.style.color=fresh&&data.status==='ok'?'var(--text-primary)':'var(--wrt-card-title-color)';
        const updated=Number(data.seen)>0?new Date(data.seen*1000).toLocaleTimeString():msg('尚未成功取得資料','No successful sample');
        subtitle.textContent=(data.name||'CCR2216')+' · 192.168.100.1 · '+(data.model||'CCR2216')+' · RouterOS '+(data.version||'—')+' · '+msg('最後成功讀取 ','Last successful sample ')+updated;
        metrics.replaceChildren();health.replaceChildren();ports.replaceChildren();rows.replaceChildren();
        if(!fresh){metric('CPU','—');metric('RAM','—');metric(msg('溫度','Temperature'),'—');return;}
        const up=Number(data.uptime_s),mem=valid(data.memory_total)&&data.memory_total>0&&valid(data.memory_free)&&data.memory_free<=data.memory_total?100*(1-data.memory_free/data.memory_total):null;
        metric('CPU',number(data.cpu,' %'));metric('RAM',number(mem,' %')+(valid(data.memory_total)?' / '+number(data.memory_total/1073741824,' GiB'):''));
        const temp=data.health.find(h=>h.name==='cpu-temperature');metric(msg('CPU 溫度','CPU temperature'),temp?number(Number(temp.value),' °C'):'—');
        metric(msg('運行時間','Uptime'),valid(up)?Math.floor(up/86400)+msg(' 天 ',' d ')+Math.floor(up%86400/3600)+msg(' 時 ',' h ')+Math.floor(up%3600/60)+msg(' 分',' m'):'—');
        const wan=data.ports.filter(p=>p.wan),rx=wan.length&&wan.every(p=>valid(p.rx_mbps))?wan.reduce((a,p)=>a+p.rx_mbps,0):null,tx=wan.length&&wan.every(p=>valid(p.tx_mbps))?wan.reduce((a,p)=>a+p.tx_mbps,0):null;
        metric('WAN '+msg('接收','RX'),traffic(rx));metric('WAN '+msg('送出','TX'),traffic(tx));
        const labels={'fan-state':msg('風扇','Fans'),'psu1-state':msg('電源 1','PSU 1'),'psu2-state':msg('電源 2','PSU 2'),'switch-temperature':msg('交換晶片','Switch chip'),'sfp-temperature':'SFP','board-temperature1':msg('主板 1','Board 1'),'board-temperature2':msg('主板 2','Board 2')};
        for(const h of data.health){
            if(h.name==='cpu-temperature')continue;
            const item=el('span',(labels[h.name]||h.name)+': '+h.value+(h.unit==='C'?' °C':h.unit?' '+h.unit:''),'border rounded px-2 py-1');
            health.appendChild(item);
        }
        for(const group of ccrPhysicalGroups(data.ports)){
            const active=group.ports.filter(p=>p.up&&!p.disabled),disabled=group.ports.every(p=>p.disabled);
            const tile=el('div',undefined,'border rounded p-2');tile.style.minWidth='0';
            const label=group.key==='ether1'?'Ethernet 1':group.key.replace('qsfp28-','QSFP28 ').replace('sfp28-','SFP28 ');
            const name=el('div',label,'fw-bold');const dot=el('span');dot.setAttribute('aria-hidden','true');dot.style.cssText='display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:'+(active.length?'#2fbb89':'#88909c');name.prepend(dot);tile.appendChild(name);
            tile.appendChild(el('div',active.length?active.map(p=>p.speed||msg('速率未知','Unknown rate')).join(' + '):disabled?msg('已停用','Disabled'):msg('未連線','Disconnected')));
            const peers=[...new Set(active.flatMap(p=>p.peers||[]))];
            const info=[group.ports.some(p=>p.wan)?'WAN':'',...peers].filter(Boolean).join(' · ');
            const peer=el('small',info||'\u00a0','setting-info d-block');peer.style.overflowWrap='anywhere';tile.appendChild(peer);
            ports.appendChild(tile);
        }
        for(const p of data.ports){
            const row=rows.insertRow();[p.name+(p.wan?' · WAN':''),p.disabled?msg('已停用','Disabled'):p.up?(p.speed||'—'):msg('未連線','Disconnected'),traffic(p.rx_mbps),traffic(p.tx_mbps),number(p.rx_errors)+' / '+number(p.tx_errors),number(p.rx_drops)+' / '+number(p.tx_drops)].forEach(value=>{row.insertCell().textContent=value;});
        }
        if(data.errors?.length)status.textContent+=' · '+data.errors.join(', ');
    }
    async function refresh(){
        if(!root.isConnected)return;
        try{
            const query=new URLSearchParams({db:'ccr_status',ts:'0',duration:'0',point:'0',limit:'1',order_by:'DESC',content:'data_time;payload'});
            const response=await fetch('/get_diag_content_data.cgi?'+query,{cache:'no-store',signal:AbortSignal.timeout(8000)});
            if(!response.ok)throw new Error('CCR query failed');
            last=parseCcrStatus(await response.json());if(root.isConnected)render(last);
        }catch(_){
            if(root.isConnected)render({...last,status:'unavailable'});
        }finally{if(root.isConnected)setTimeout(refresh,15000);}
    }
    refresh();
}
