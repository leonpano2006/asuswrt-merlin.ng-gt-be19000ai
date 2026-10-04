function startNodeWirelessClients() {
const canvas = document.getElementById('chart_clients');
if (!canvas || canvas.dataset.nodeClients) return;
canvas.dataset.nodeClients = '1';
const card = canvas.closest('.card');
card.querySelector('.card-header').textContent = '本機無線連線';
const insight = createNodeWifiInsight();
window.nodeInsightLocal = insight;
const labels = ['無線合計', '2.4 GHz', '5 / 6 GHz'];
card.querySelectorAll('.card-data-title').forEach((node, i) => {if (labels[i]) node.textContent = labels[i];});
const countNodes = ['client_all_count','wireless_count','wired_count'].map(id => document.getElementById(id));
const details = document.getElementById('wifi_client_table');
details.replaceChildren();
const note = document.createElement('p');
note.className = 'px-3';
note.textContent = '顯示本機各頻段已授權的連線；MLO 可能讓同一台裝置出現在多個頻段。';
details.appendChild(note);
let chart = null;
async function sampleClients() {
if (!canvas.isConnected) {if (chart) chart.destroy(); return;}
try {
const response = await fetch('/ajax_wificlients.asp', {cache:'no-store', signal:AbortSignal.timeout(4000)});
if (!response.ok) throw new Error('Wireless status unavailable');
const text = await response.text();
const snapshot = parseNodeWirelessSnapshot(text);
const counts = snapshot.radios.map(r => r.count);
if (!canvas.isConnected) return;
insight.update(snapshot);
countNodes[0].textContent = counts.reduce((a,b)=>a+b,0);
countNodes[1].textContent = counts[0];
countNodes[2].textContent = counts[1] + ' / ' + counts[2];
if (!chart) {
const old = Chart.getChart(canvas); if(old) old.destroy();
const css=getComputedStyle(document.documentElement);
chart = new Chart(canvas,{type:'doughnut',data:{labels:['2.4 GHz','5 GHz','6 GHz'],datasets:[{data:counts,backgroundColor:['#ff8694','#64d5ed','#b29bff'],borderColor:'transparent'}]},options:{responsive:true,maintainAspectRatio:false,cutout:'70%',plugins:{legend:{position:'right',labels:{color:css.getPropertyValue('--text-primary')}}}}});
} else {chart.data.datasets[0].data=counts;chart.update('none');}
} catch(error) {if(canvas.isConnected){countNodes.forEach(node=>node.textContent='—');insight.fail();}console.warn('Local wireless status:',error.message);}
if(canvas.isConnected)setTimeout(sampleClients,5000);
}
sampleClients();
}
