// Parse vendor status as data; never evaluate a response as JavaScript.
function parseNodeWirelessSnapshot(text) {
    function assignment(name) {
        const marker = name + ' =';
        const start = text.indexOf(marker);
        if (start < 0) return [];
        const opening = text.indexOf('[', start + marker.length);
        if (opening < 0) throw new Error('Missing wireless array');
        let depth = 0, quoted = false, escaped = false, end = -1;
        for (let i = opening; i < text.length; i++) {
            const c = text[i];
            if (quoted) {
                if (escaped) escaped = false;
                else if (c === String.fromCharCode(92)) escaped = true;
                else if (c === '"') quoted = false;
            } else if (c === '"') quoted = true;
            else if (c === '[') depth++;
            else if (c === ']' && --depth === 0) {end = i + 1; break;}
        }
        if (end < 0) throw new Error('Incomplete wireless array');
        const data = JSON.parse(text.slice(opening, end));
        if (!Array.isArray(data)) throw new Error('Invalid wireless array');
        return data;
    }
    const marker = text.indexOf('var nvram_dump_String');
    const start = marker < 0 ? -1 : text.indexOf('/*', marker);
    const end = text.lastIndexOf('*/}.toString()');
    const detail = start >= 0 && end > start ? text.slice(start + 2, end).trim() : '';
    const sections = detail.split(/(?=^SSID: ")/m);
    const labels = ['2.4 GHz', '5 GHz', '6 GHz'];
    const byBand = {};
    for (const section of sections) {
        const band = section.match(/Chanspec:\s*(2\.4|5|6)GHz/);
        const ssid = section.match(/^SSID: "(.*)"\s*$/m);
        const bssid = section.match(/^BSSID:\s*([0-9a-f:]{17})/mi);
        const channel = section.match(/\bChannel:\s*(\S+)/);
        if (!band || !ssid || !bssid || !channel) continue;
        const primary = section.match(/Primary channel:\s*(\d+)/);
        const bandwidth = section.match(/Chanspec:.*?\s(\d+)MHz/);
        const noise = section.match(/noise:\s*(-?\d+)\s*dBm/);
        const utilization = section.match(/QBSS Channel Utilization:.*?\((\d+)\s*%/);
        const mode = section.match(/^Mode\s*:\s*(.+)$/m);
        byBand[band[1] + ' GHz'] = {ssid:ssid[1], bssid:bssid[1], channel:channel[1],
            primaryChannel:primary ? Number(primary[1]) : null,
            bandwidth:bandwidth ? Number(bandwidth[1]) : null,
            noise:noise ? Number(noise[1]) : null,
            utilization:utilization ? Number(utilization[1]) : null,
            mode:mode ? mode[1].trim() : 'AP'};
    }
    const radios = labels.map((label, unit) => {
        const clients = assignment('wificlients' + unit).filter(Array.isArray);
        if (clients.some(c => c.length < 14)) throw new Error('Invalid client record');
        const authorized = clients.filter(c => String(c[11]).includes('A') && String(c[11]).includes('U'));
        const header = assignment('dataarray' + unit);
        const live = byBand[label] || null;
        const count = new Set(authorized.map(c => String(c[0]).toUpperCase())).size;
        return {unit, label, header, clients, count, live, dfs:assignment('dfs_statusarray' + unit)};
    });
    if (!radios.some(r => r.header.length || r.clients.length || r.live)) throw new Error('No wireless status in response');
    return {radios, detail};
}
