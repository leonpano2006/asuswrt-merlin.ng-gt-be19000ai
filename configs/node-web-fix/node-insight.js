function createNodeWifiInsight() {
    const target = document.getElementById('WiFiInterferenceView');
    if (!target) return {update:function(){}, fail:function(){}};
    target.replaceChildren();
    target.classList.add('card','p-3');
    const title = document.createElement('h5');
    title.className = 'card-header'; title.textContent = 'WiFi Insight｜本機即時與歷史';
    const note = document.createElement('p');
    note.className = 'px-3';
    note.textContent = '顯示本機 AP 的即時頻道與無線連線。即時頻道使用率來自 AP 的 QBSS 讀數；下方歷史來自驅動的被動頻道統計。MLO 各頻段的連線可能屬於同一台裝置。';
    const stamp = document.createElement('p'); stamp.className = 'px-3'; stamp.setAttribute('role','status');
    const wrap = document.createElement('div'); wrap.className = 'table-responsive px-3';
    const table = document.createElement('table'); table.className = 'table align-middle';
    const thead = document.createElement('thead'); const row = document.createElement('tr');
    ['頻段','SSID','主頻道／頻寬','BSSID','頻道使用率','底噪','已授權連線'].forEach(label => {
        const th = document.createElement('th');th.textContent=label;row.appendChild(th);
    });
    thead.appendChild(row); const body = document.createElement('tbody');
    table.append(thead,body);wrap.appendChild(table);target.append(title,note,stamp,wrap);
    const historyTitle=document.createElement('h6');historyTitle.className='px-3 mt-4';historyTitle.textContent='頻道占用歷史';
    const bandSelect=document.createElement('select');bandSelect.className='form-select w-auto mx-3';bandSelect.setAttribute('aria-label','WiFi Insight 頻段');
    ['2.4 GHz','5 GHz','6 GHz'].forEach((label,unit)=>{const option=document.createElement('option');option.value=unit;option.textContent=label;bandSelect.appendChild(option);});
    const historyNote=document.createElement('p');historyNote.className='px-3';historyNote.textContent='OBSS 是其他 BSS 的占用；NOPKT 是有能量但未解出封包的占用，不能據此判定干擾源。這不是 FFT 頻譜圖。時間範圍跟隨上方歷史選單。';
    const historyStatus=document.createElement('p');historyStatus.className='px-3';historyStatus.id='node_insight_history_status';historyStatus.setAttribute('role','status');
    const chartWrap=document.createElement('div');chartWrap.className='px-3';chartWrap.style.height='280px';const canvas=document.createElement('canvas');canvas.id='node_insight_airtime';chartWrap.appendChild(canvas);
    const events=document.createElement('div');events.className='px-3';
    target.append(historyTitle,bandSelect,historyNote,historyStatus,chartWrap,events);
    let historyRows=[],chart=null;
    function renderHistory() {
        if(!target.isConnected){if(chart)chart.destroy();return;}
        const rows=historyRows.filter(r=>r.kind==='radio'&&r.band===Number(bandSelect.value));
        if(chart)chart.destroy();
        chart=nodeHistoryChart(canvas,[nodeHistorySeries('總占用',rows,'busy','#db5471'),nodeHistorySeries('其他 BSS（OBSS）',rows,'obss','#20839b'),nodeHistorySeries('未解碼占用（NOPKT）',rows,'nopkt','#9170cd')],100,' %');
        const last=rows[rows.length-1];
        historyStatus.textContent=!last?'等待歷史記錄。':Date.now()/1000-last.time>150?'記錄已過期；最後更新 '+new Date(last.time*1000).toLocaleString():last.on===0?'此頻段無線電已關閉。':last.busy===null?'驅動未提供頻道占用資料。':'最新底噪：'+(last.noise===null?'—':last.noise+' dBm')+'｜記錄 '+rows.length+' 筆';
        events.replaceChildren();const label=document.createElement('p');label.textContent='觀測到的頻道／頻寬變化（每分鐘取樣；不包含變更原因）';events.appendChild(label);
        let previous=null;const changes=[];
        rows.forEach(r=>{if(previous&&r.channel&&previous.channel&&r.channel!==previous.channel&&r.time-previous.time<=180&&r.uptime>previous.uptime)changes.push(new Date(r.time*1000).toLocaleString()+'：'+previous.channel+' → '+r.channel);previous=r;});
        const list=document.createElement('ul');(changes.length?changes.slice(-20).reverse():['此時段未觀測到頻道變化。']).forEach(text=>{const item=document.createElement('li');item.textContent=text;list.appendChild(item);});events.appendChild(list);
    }
    bandSelect.addEventListener('change',renderHistory);
    return {
        updateHistory:function(rows){historyRows=rows;renderHistory();},
        historyFail:function(){historyStatus.textContent='歷史資料暫時無法取得。';if(chart){chart.destroy();chart=null;}events.replaceChildren();},
        update:function(snapshot) {
            body.replaceChildren();
            snapshot.radios.forEach(r => {
                const tr=document.createElement('tr'), x=r.live;
                const values=[r.label,x ? x.ssid : '狀態未提供',x ? (x.primaryChannel === null ? x.channel : x.primaryChannel)+' / '+(x.bandwidth === null ? '—' : x.bandwidth+' MHz') : '—',
                    x ? x.bssid : '—', x && x.utilization !== null ? x.utilization+' %' : '—',
                    x && x.noise !== null ? x.noise+' dBm' : '—',String(r.count)];
                values.forEach(value=>{const td=document.createElement('td');td.textContent=value;tr.appendChild(td);});body.appendChild(tr);
            });
            stamp.textContent='更新：'+new Date().toLocaleTimeString();
        },
        fail:function(){body.replaceChildren();stamp.textContent='即時資料暫時無法取得；未顯示過期數字。';}
    };
}
