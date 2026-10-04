// Local observability, using the same authenticated snapshot as the CCR card.
function networkFilter(devices,query,state,port) {
    const q=query.trim().toLocaleLowerCase();
    return devices.filter(d=>(!state||d.state===state)&&(!port||d.via.includes(port))&&
        (!q||[d.name,d.mac,...d.ips,...(d.cached_ips||[]),d.reserved_ip,...d.via].join(' ').toLocaleLowerCase().includes(q)));
}
function networkPeerGroups(peers) {
    const result=[];
    for(const p of peers){
        // Join advertisements on different Cisco member ports only when identity,
        // model AND management IP agree. Do not join arbitrary same-name clients.
        const key=p.ip?[p.ip,p.name,p.model].join('|'):p.mac;
        let g=result.find(x=>x.key===key);
        if(!g){g={key,...p,paths:[]};result.push(g);}
        g.paths.push({via:p.via,kind:p.kind});
    }
    return result;
}
function createNetworkOverview() {
    const root=document.getElementById('networkOverview');
    if(!root)return {update(){}};
    const tw=system.language.currentLang==='TW',t=(zh,en)=>tw?zh:en;
    const el=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
    const css=el('style');css.textContent=`
    #networkOverview .net-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
    #networkOverview .net-small{font-size:.86rem;overflow-wrap:anywhere}
    #networkOverview .net-muted{color:var(--text-primary);opacity:.78}
    #networkOverview #networkBranches{border-top:2px solid #6c788c;padding-top:14px}
    #networkOverview .net-branch{border:1px solid #6c788c;border-radius:8px;padding:12px;min-width:0}
    #networkOverview .net-peer{border-left:3px solid #41bda0;padding-left:9px;margin:10px 0}
    #networkOverview .net-peer.indirect{border-left:3px dashed #93a0b5}
    #networkOverview .net-tabs{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}
    #networkOverview .net-tabs button[aria-selected=true]{background:var(--wrt-primary,#b82047);color:var(--wrt-primary-text-color,#fff);border-color:var(--wrt-primary,#b82047)}
    #networkOverview .net-table-wrap{max-height:390px;overflow:auto}
    #networkOverview th{white-space:nowrap} #networkOverview td{vertical-align:middle;overflow-wrap:anywhere}
    #networkOverview .net-up{color:#40c5a2} #networkOverview .net-warn{color:#edb35f}
    #networkOverview [hidden]{display:none!important}
    #networkOverview .net-focus{color:var(--text-primary);border-color:#778395}
    #networkOverview .net-focus:hover{background:rgba(129,145,169,.17);color:var(--text-primary)}
    #networkOverview .net-focus:focus-visible{outline:2px solid #68b5ff;outline-offset:3px}
    `;
    const head=el('div',undefined,'d-flex flex-wrap align-items-center justify-content-between');
    head.append(el('h5',t('網路總覽','Network overview'),'card-header mb-0'),el('span',t('本地收集 · 唯讀','Local · Read only'),'net-small net-muted me-3'));
    const body=el('div',undefined,'card-body');
    const status=el('p',t('正在收集網路狀態…','Collecting network status…'),'net-small mb-3');status.id='networkStatus';status.setAttribute('role','status');
    const metrics=el('div',undefined,'net-grid');metrics.id='networkMetrics';
    const tabs=el('div',undefined,'net-tabs');tabs.setAttribute('role','tablist');tabs.setAttribute('aria-label',t('網路總覽檢視','Network overview views'));
    const panels={},buttons={};let tab='topology',last=null,usable=false,selected=null;
    function selectTab(id){tab=id;for(const key of Object.keys(panels)){panels[key].hidden=key!==id;buttons[key].setAttribute('aria-selected',String(key===id));buttons[key].tabIndex=key===id?0:-1;}}
    [['topology',t('連接拓撲','Topology')],['devices',t('設備清單','Devices')],['issues',t('異常與事件','Issues & events')]].forEach(([id,label])=>{
        const b=el('button',label,'btn btn-outline-primary net-focus');b.type='button';b.setAttribute('role','tab');b.id='network-tab-'+id;b.setAttribute('aria-controls','network-'+id);
        b.addEventListener('click',()=>selectTab(id));b.addEventListener('keydown',e=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;e.preventDefault();const ids=Object.keys(buttons),i=ids.indexOf(id),n=e.key==='Home'?0:e.key==='End'?ids.length-1:(i+(e.key==='ArrowRight'?1:-1)+ids.length)%ids.length;selectTab(ids[n]);buttons[ids[n]].focus();});
        const p=el('div');p.id='network-'+id;p.setAttribute('role','tabpanel');p.setAttribute('aria-labelledby',b.id);panels[id]=p;buttons[id]=b;tabs.appendChild(b);
    });
    const topo=panels.topology;
    const topoNote=el('p',t('以 CCR2216 為中心。LLDP 鄰居用實線；其他探索用虛線。MAC 表表示「經由此埠」，不代表直接插在此埠。','CCR2216 view: solid markers indicate LLDP neighbors; dashed markers indicate other discovery. MAC paths mean “via this port”, not a direct cable.'),'net-small net-muted');
    const hub=el('div',undefined,'border rounded p-3 mb-3');
    const branches=el('div',undefined,'net-grid');branches.id='networkBranches';topo.append(topoNote,hub,branches);
    const devicePanel=panels.devices,toolbar=el('div',undefined,'d-flex flex-wrap gap-2 mb-3');
    const search=el('input',undefined,'form-control');search.type='search';search.placeholder=t('搜尋名稱、IP、MAC 或連接埠','Search name, IP, MAC or port');search.setAttribute('aria-label',search.placeholder);search.style.cssText='flex:2;min-width:210px';
    const state=el('select',undefined,'form-select');state.style.cssText='flex:1;min-width:160px';state.setAttribute('aria-label',t('篩選可見狀態','Filter visibility'));
    [['',t('全部狀態','All states')],['seen',t('近期可見','Recently seen')],['unknown',t('狀態未確認','Unconfirmed')]].forEach(([v,text])=>{const o=el('option',text);o.value=v;state.appendChild(o);});
    const port=el('select',undefined,'form-select');port.style.cssText='flex:1;min-width:160px';port.setAttribute('aria-label',t('篩選連接埠','Filter port'));
    const reset=el('button',t('清除篩選','Clear filters'),'btn btn-outline-primary net-focus');reset.type='button';reset.addEventListener('click',()=>{search.value='';state.value='';port.value='';renderDevices();});
    toolbar.append(search,state,port,reset);
    const listCount=el('p','','net-small net-muted');listCount.id='networkListCount';
    const wrapper=el('div',undefined,'net-table-wrap');const table=el('table',undefined,'table');table.setAttribute('aria-label',t('網路設備清單','Network device inventory'));
    const tr=table.createTHead().insertRow();[t('名稱／MAC','Name / MAC'),'IP',t('可見狀態','Visibility'),t('經由 CCR 介面','Via CCR interface'),t('資料來源','Evidence'),t('詳細資料','Details')].forEach(x=>{const h=el('th',x);h.scope='col';tr.appendChild(h);});
    const rows=table.createTBody();wrapper.appendChild(table);const inspector=el('div',undefined,'border rounded p-3 mt-3');inspector.hidden=true;inspector.id='networkDeviceDetails';
    devicePanel.append(toolbar,listCount,wrapper,inspector,el('p',t('每列是一個 MAC 記錄，不等於實體設備數。近期可見以 ARP reachable 或 MAC 學習表為依據；租約、ARP 快取不能單獨證明在線。此處不推測 Wi-Fi SSID。','Each row is a MAC record, not necessarily a physical device. Recent visibility uses ARP reachable or the MAC learning table; leases and ARP caches alone do not prove connectivity. Wi-Fi SSIDs are not inferred here.'),'net-small net-muted mt-3 mb-0'));
    const issueList=el('div');issueList.id='networkIssues';const events=el('div',undefined,'mt-3');events.id='networkEvents';
    panels.issues.append(issueList,el('h6',t('最近事件','Recent events'),'mt-4'),events,el('p',t('事件僅記錄開始監看之後的變化，保留最近 24 小時、最多 30 筆；資料存於 RAM，BE19000AI 重開後清空。','Events begin with monitoring and retain up to 30 entries over 24 hours in RAM. Rebooting BE19000AI clears them.'),'net-small net-muted mt-3 mb-0'));
    body.append(status,metrics,tabs,...Object.values(panels));root.replaceChildren(css,head,body);selectTab(tab);
    function evidence(d){return d.evidence.map(k=>({'arp-reachable':'ARP reachable',fdb:t('MAC 學習表','MAC table'),dhcp:'DHCP',arp:t('ARP 快取','ARP cache')})[k]||k).join(' · ');}
    function renderDevices(){
        rows.replaceChildren();inspector.hidden=true;
        if(!usable){listCount.textContent=t('資料尚未可用','No current data');return;}
        const all=last.network.devices,shown=networkFilter(all,search.value,state.value,port.value);
        listCount.textContent=t('顯示 ','Showing ')+shown.length+' / '+all.length+t(' 筆 MAC 記錄',' MAC records');
        for(const d of shown){const r=rows.insertRow(),name=r.insertCell();name.append(el('div',d.name||t('未命名','Unnamed'),'fw-bold'),el('div',d.mac,'net-small net-muted'));
            const ip=d.ips.join(', ')||(d.cached_ips?.length?d.cached_ips.join(', ')+t('（快取）',' (cached)'):d.reserved_ip?d.reserved_ip+t('（預留）',' (reservation)'):'—');
            [ip,d.state==='seen'?t('近期可見','Recently seen'):t('狀態未確認','Unconfirmed'),d.via.join(', ')||t('路徑未確認','Path unknown'),evidence(d)].forEach(v=>r.insertCell().textContent=v);
            const b=el('button',t('查看','Inspect'),'btn btn-outline-primary btn-sm net-focus');b.type='button';b.setAttribute('aria-label',t('查看 ','Inspect ')+(d.name||d.mac));b.addEventListener('click',()=>{selected=d.mac;inspect(d);});r.insertCell().appendChild(b);
        }
        if(!shown.length){const c=rows.insertRow().insertCell();c.colSpan=6;c.textContent=t('沒有符合篩選的記錄','No records match these filters');}
        if(selected){const d=shown.find(x=>x.mac===selected);if(d)inspect(d);}
    }
    function inspect(d){inspector.replaceChildren(el('strong',(d.name||t('未命名','Unnamed'))+' · '+d.mac));
        inspector.append(el('div',t('觀測 IP：','Observed IP: ')+(d.ips.join(', ')||'—')),el('div',t('未重新確認的 ARP IP：','Unconfirmed ARP IP: ')+((d.cached_ips||[]).join(', ')||'—')),el('div',t('ARP 狀態：','ARP state: ')+(d.arp.join(', ')||'—')),el('div',t('DHCP 租約：','DHCP lease: ')+(d.lease||'—')),el('div',t('路徑依據：','Path evidence: ')+(d.via.length?'CCR2216 MAC → '+d.via.join(', '):t('沒有 MAC 學習記錄','No learned MAC path'))));inspector.hidden=false;}
    search.addEventListener('input',renderDevices);state.addEventListener('change',renderDevices);port.addEventListener('change',renderDevices);
    function metric(label,value){const box=el('div',undefined,'border rounded p-2');box.append(el('div',label,'net-small net-muted'),el('div',String(value),'fs-4 fw-bold'));metrics.appendChild(box);}
    function issueText(x){switch(x.kind){case 'collection':return t('部分來源無法讀取：','Sources unavailable: ')+x.target;case 'wan-route':return t('未找到啟用中的 IPv4 預設路由','No active IPv4 default route');case 'health':return x.target+' · '+x.detail;case 'link-down':return x.target+t('：先前有連線，目前未連線；請確認是否預期',' was connected and is now down; check if expected');case 'counter':return x.target+' · '+x.detail+' +'+x.value+t('（本次採樣）',' (this sample)');default:return x.target||x.kind;}}
    const eventLabels={'link-up':t('連線建立','Link up'),'link-down':t('連線中斷','Link down'),reboot:t('偵測到 CCR 重開','CCR restart detected'),gap:t('收集恢復；中間狀態未知','Collection resumed; gap state unknown'),started:t('開始記錄事件','Event monitoring started')};
    return {update(data,fresh){
        last=data;usable=fresh&&data.network?.schema===1&&Array.isArray(data.network.devices)&&Array.isArray(data.network.peers);
        metrics.replaceChildren();branches.replaceChildren();hub.replaceChildren();issueList.replaceChildren();events.replaceChildren();
        if(!usable){status.textContent=t('網路資料過期或無法讀取；不再顯示舊資料為即時狀態。','Network data is stale or unavailable; old data is not shown as current.');status.className='net-warn net-small';
            [t('MAC 記錄','MAC records'),t('近期可見','Recently seen'),t('探索到的網路設備','Discovered infrastructure'),t('異常','Issues')].forEach(x=>metric(x,'—'));
            issueList.textContent=status.textContent;hub.textContent=t('等待下一次成功收集','Waiting for a successful sample');renderDevices();return;
        }
        const n=data.network,peers=networkPeerGroups(n.peers),issues=n.issues||[];
        status.className='net-small net-muted mb-3';status.textContent='CCR2216 · '+n.scope+' · '+t('更新 ','Updated ')+new Date(data.seen*1000).toLocaleTimeString()+' · '+(data.status==='partial'?t('部分來源缺失','Some sources missing'):t('約每 30 秒收集','Collected about every 30 seconds'))+(n.truncated?t(' · 記錄超過顯示上限',' · Display limit reached'):'');
        metric(t('MAC 記錄','MAC records'),n.total);metric(t('近期可見','Recently seen'),n.seen_total);metric(t('探索到的網路設備','Discovered infrastructure'),peers.length);metric(t('需留意','Needs attention'),issues.length);
        hub.append(el('strong','CCR2216 · 192.168.100.1'),el('div',t('下方按 CCR 的介面分組；點擊「查看經由此埠的設備」可追查路徑。','Grouped by CCR interface. Select “View devices via this port” to investigate a path.'),'net-small net-muted'));
        const keys=[...new Set([...data.ports.filter(p=>p.up||n.peers.some(x=>x.via===p.name)).map(p=>p.name),...n.devices.flatMap(d=>d.via)])];
        for(const key of keys){const p=data.ports.find(x=>x.name===key),ps=n.peers.filter(x=>x.via===key),ds=n.devices.filter(d=>d.via.includes(key));
            const branch=el('div',undefined,'net-branch');branch.append(el('div',key+(p?.wan?' · WAN':''),'fw-bold'),el('div',p?(p.up?(p.speed||t('速率未知','Unknown rate')):t('未連線','Link down')):t('邏輯介面／聚合','Logical interface / bond'),'net-small '+(p?.up?'net-up':'net-muted')));
            for(const peer of ps){const item=el('div',undefined,'net-peer'+(peer.kind==='lldp'?'':' indirect'));item.append(el('div',peer.name||peer.mac,'fw-bold'),el('div',peer.ip||t('管理 IP 未確認','Management IP unknown'),'net-small'),el('div',peer.model||peer.protocols.join(' / '),'net-small net-muted'),el('div',peer.kind==='lldp'?t('LLDP 鄰居','LLDP neighbor'):t('探索可見 · 中間接線未確認','Discovered · intervening links unconfirmed'),'net-small net-muted'));branch.appendChild(item);}
            if(!ps.length)branch.append(el('div',p?.wan?t('上游網路','Upstream network'):t('未取得鄰居身分','Neighbor identity unavailable'),'net-small net-muted mt-2'));
            if(ds.length){const b=el('button',t('查看經由此埠的設備','View devices via this port')+' · '+ds.length,'btn btn-outline-primary btn-sm mt-2 net-focus');b.type='button';b.setAttribute('aria-label',key+' '+t('查看設備','view devices'));b.addEventListener('click',()=>{search.value='';state.value='';port.value=key;selected=null;renderDevices();selectTab('devices');buttons.devices.focus();});branch.appendChild(b);}
            branches.appendChild(branch);
        }
        const old=port.value;port.replaceChildren();const opt=el('option',t('所有連接埠','All ports'));opt.value='';port.appendChild(opt);
        [...new Set(n.devices.flatMap(d=>d.via))].sort().forEach(key=>{const o=el('option',key);o.value=key;port.appendChild(o);});port.value=[...port.options].some(x=>x.value===old)?old:'';
        if(issues.length){for(const x of issues)issueList.append(el('div',issueText(x),'border rounded p-2 mb-2 net-warn'));}
        else issueList.append(el('div',t('目前未偵測到監測範圍內的異常','No issues detected within the monitored scope'),'net-up'),el('p',t('涵蓋收集狀態、預設路由、電源／風扇、先前活動埠及新增錯誤計數；不表示每台用戶端皆正常。','Covers collection, default route, PSU/fans, previously active links and counter increases. This does not certify every client is healthy.'),'net-small net-muted mt-2'));
        for(const e of n.events||[])events.append(el('div',new Date(e.at*1000).toLocaleString()+' · '+(eventLabels[e.kind]||e.kind)+' · '+e.target,'net-small border-bottom py-2'));
        buttons.issues.textContent=t('異常與事件','Issues & events')+(issues.length?' · '+issues.length:'');renderDevices();
    }};
}
