// Local RAM history is queried through the stock authenticated diagnostic API.
function parseNodeHistory(payload) {
    if (!payload || !Array.isArray(payload.contents)) throw new Error('歷史 API 未提供資料');
    const num = value => value === null || value === '' || value === undefined || Number(value) === -1 || Number(value) === -999 ? null : (Number.isFinite(Number(value)) ? Number(value) : null);
    return payload.contents.map(r => {
        if (!Array.isArray(r) || r.length !== 14) throw new Error('歷史資料格式不符');
        return {time:num(r[0]),kind:r[1],iface:r[2],band:num(r[3]),rx:num(r[4]),tx:num(r[5]),links:num(r[6]),channel:r[7],busy:num(r[8]),obss:num(r[9]),nopkt:num(r[10]),noise:num(r[11]),on:num(r[12]),uptime:num(r[13])};
    }).filter(r => r.time !== null && ['interface','radio'].includes(r.kind)).sort((a,b)=>a.time-b.time);
}
function nodeHistoryPoints(rows, field) {
    const points=[];let last=null;
    for(const row of rows) {
        // Leave visible gaps after sampler outages, reboots or clock jumps.
        if(last && (row.time-last.time>180 || row.uptime<last.uptime || Math.abs((row.time-last.time)-(row.uptime-last.uptime))>10)) points.push({x:(last.time+1)*1000,y:null});
        points.push({x:row.time*1000,y:row[field]});last=row;
    }
    return points;
}
function nodeHistoryChart(canvas, datasets, maximum, unit) {
    const css=getComputedStyle(document.documentElement),color=css.getPropertyValue('--text-primary').trim()||'#89939e';
    const previous=Chart.getChart(canvas);if(previous)previous.destroy();
    return new Chart(canvas,{type:'line',data:{datasets},options:{responsive:true,maintainAspectRatio:false,animation:false,parsing:false,spanGaps:false,
        interaction:{mode:'nearest',axis:'x',intersect:false},
        plugins:{legend:{labels:{color}},tooltip:{callbacks:{title:items=>items.length?new Date(items[0].parsed.x).toLocaleString():''}}},
        scales:{x:{type:'linear',ticks:{color,maxTicksLimit:6,callback:value=>new Date(value).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}},
            y:{min:unit===' dBm'?undefined:0,max:maximum,ticks:{color,callback:value=>value+unit}}}}});
}
function nodeHistorySeries(label, rows, field, color) {
    return {label,data:nodeHistoryPoints(rows,field),borderColor:color,backgroundColor:color,borderWidth:2,pointRadius:1,spanGaps:false};
}
function startNodeHistory() {
    const oldCanvas=document.getElementById('bw_chart');if(!oldCanvas||oldCanvas.dataset.nodeHistory)return;
    oldCanvas.dataset.nodeHistory='1';
    const card=oldCanvas.closest('.card');card.replaceChildren();
    function element(tag,text,cls) {const e=document.createElement(tag);if(text)e.textContent=text;if(cls)e.className=cls;return e;}
    card.appendChild(element('h5','本機流量與連線歷史','card-header'));
    const body=element('div','','card-body');card.appendChild(body);
    const controls=element('div','','d-flex flex-wrap gap-3 mb-3');
    const iface=element('select','','form-select w-auto');iface.id='node_history_interface';iface.setAttribute('aria-label','流量介面');
    const period=element('select','','form-select w-auto');period.id='node_history_period';period.setAttribute('aria-label','歷史時間範圍');
    [[1800,'最近 30 分鐘'],[21600,'最近 6 小時'],[86400,'最近 24 小時']].forEach(([value,label])=>{const option=element('option',label);option.value=value;period.appendChild(option);});
    controls.append(element('label','流量介面'),iface,element('label','時間範圍'),period);body.appendChild(controls);
    body.appendChild(element('p','每分鐘記錄，保留最近 24 小時；關閉網頁仍會記錄，重開機後重新累積。流量是所選介面收到／送出的核心計數，不是 WAN 帳務流量；硬體加速路徑的涵蓋範圍依驅動而定。Bond 與成員埠不相加。'));
    const status=element('p','','fw-bold');status.id='node_history_status';status.setAttribute('role','status');body.appendChild(status);
    const trafficWrap=element('div');trafficWrap.style.height='280px';const traffic=element('canvas');traffic.id='node_history_traffic';trafficWrap.appendChild(traffic);body.appendChild(trafficWrap);
    body.appendChild(element('h6','各頻段已授權連線（MLO 可重複計入同一裝置）','mt-4'));
    const countWrap=element('div');countWrap.style.height='220px';const clients=element('canvas');clients.id='node_history_clients';countWrap.appendChild(clients);body.appendChild(countWrap);
    let rows=[],charts=[],stopped=false;
    const colors=['#db5471','#20839b','#9170cd'];
    function render() {
        if(!card.isConnected){stopped=true;charts.forEach(c=>c.destroy());return;}
        const names=[...new Set(rows.filter(r=>r.kind==='interface').map(r=>r.iface))].sort();
        const selected=iface.value;
        iface.replaceChildren();names.forEach(name=>{const option=element('option',name==='eth.ai'?'AI 板內部連線（eth.ai）':name);option.value=name;iface.appendChild(option);});
        iface.value=names.includes(selected)?selected:(names.includes('bond0')?'bond0':names[0]||'');
        const cutoff=Date.now()/1000-Number(period.value);
        const visible=rows.filter(r=>r.time>=cutoff);
        const trafficRows=visible.filter(r=>r.kind==='interface'&&r.iface===iface.value);
        charts.forEach(c=>c.destroy());charts=[];
        charts.push(nodeHistoryChart(traffic,[nodeHistorySeries('接收 Mbps',trafficRows,'rx','#20839b'),nodeHistorySeries('送出 Mbps',trafficRows,'tx','#db5471')],undefined,' Mbps'));
        charts.push(nodeHistoryChart(clients,[0,1,2].map((band)=>nodeHistorySeries(['2.4 GHz','5 GHz','6 GHz'][band],visible.filter(r=>r.kind==='radio'&&r.band===band),'links',colors[band])),undefined,''));
        const last=trafficRows[trafficRows.length-1],age=last?Date.now()/1000-last.time:Infinity;
        const rate=value=>value===null?'等待下一筆計數':value.toFixed(3)+' Mbps';
        status.textContent=!last?'尚無此時段資料；等待第一筆記錄。':age>150?'記錄已過期；最後更新 '+new Date(last.time*1000).toLocaleString():iface.value+'｜接收 '+rate(last.rx)+'／送出 '+rate(last.tx)+'｜'+new Date(last.time*1000).toLocaleTimeString();
        if(window.nodeInsightLocal)window.nodeInsightLocal.updateHistory(visible);
    }
    iface.addEventListener('change',render);period.addEventListener('change',render);
    async function poll() {
        if(!card.isConnected){stopped=true;charts.forEach(c=>c.destroy());return;}
        try {
            const q=new URLSearchParams({db:'node_stats',ts:'0',duration:'0',point:'0',limit:'0',order_by:'DESC',content:'data_time;kind;iface;band;rx_mbps;tx_mbps;links;chspec;busy;obss;nopkt;noise;radio_on;uptime'});
            const response=await fetch('/get_diag_content_data.cgi?'+q,{cache:'no-store',signal:AbortSignal.timeout(10000)});
            if(!response.ok)throw new Error('HTTP '+response.status);
            rows=parseNodeHistory(await response.json());if(!card.isConnected)return;render();
        } catch(error) {
            if(card.isConnected){status.textContent='歷史資料暫時無法取得，未以 0 代替。';charts.forEach(c=>c.destroy());charts=[];if(window.nodeInsightLocal)window.nodeInsightLocal.historyFail();}
        }
        if(!stopped&&card.isConnected)setTimeout(poll,60000);
    }
    status.textContent='正在讀取本機記錄…';poll();
}
