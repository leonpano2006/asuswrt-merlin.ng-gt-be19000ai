// Use the existing authenticated ASUS API. An accepted request is not proof that
// the AI board applied it: verify the separately reported ai_sys_hostname.
function validAiHostname(name) {
    return typeof name === 'string' && /^[a-z0-9][a-z0-9_-]{4,31}$/i.test(name);
}
function aiHostnamePayload(name) {
    if (!validAiHostname(name)) throw new Error('Invalid AI hostname');
    return {action_mode: 'apply', rc_service: 'start_ai_request apply', ai_hostname: name};
}
function installAiHostnameEditor() {
    const input = document.getElementById('ai_hostname');
    const button = document.getElementById('applyBtn');
    const hint = document.getElementById('hint_ai_hostname');
    const tw = system.language.currentLang === 'TW';
    const msg = (zh, en) => tw ? zh : en;
    let savedName = input.value, busy = false;
    const display = text => { if (hint.isConnected) hint.textContent = text; };
    const post = data => new Promise((resolve, reject) => $.ajax({
        url: '/applyapp.cgi', type: 'POST', dataType: 'json', timeout: 20000,
        data: encodeURIComponent(JSON.stringify(data)), success: resolve, error: reject
    }));
    const read = () => new Promise((resolve, reject) => $.ajax({
        url: '/appGet.cgi', dataType: 'json', cache: false, timeout: 10000,
        data: {hook: 'nvram_get(ai_hostname);nvram_get(ai_sys_hostname)'},
        success: data => {
            if (typeof data.ai_hostname !== 'string' || typeof data.ai_sys_hostname !== 'string') reject(new Error('Invalid hostname response'));
            else resolve(data);
        }, error: reject
    }));
    const update = () => { button.disabled = busy || input.value === savedName; };
    input.disabled = false;
    input.addEventListener('input', () => { input.removeAttribute('aria-invalid'); display(''); update(); });
    button.addEventListener('click', async () => {
        if (busy || input.value === savedName) return;
        const name = input.value;
        if (!validAiHostname(name)) {
            input.setAttribute('aria-invalid', 'true');
            display(msg('請輸入 5–32 個英文字母、數字、底線或連字號，第一個字元須為字母或數字；不用加 .local。',
                        'Use 5–32 letters, digits, underscores or hyphens, starting with a letter or digit. Omit .local.'));
            input.focus(); return;
        }
        busy = true; input.disabled = true; update();
        let submitted = false;
        display(msg('正在傳送主機名稱…', 'Sending hostname…'));
        try {
            const before = await read();
            if (before.ai_hostname === name && before.ai_sys_hostname === name) {
                savedName = name;
                display(msg('AI 板目前已使用此名稱。', 'The AI board already uses this hostname.'));
                return;
            }
            // Do not change ai_portainer_enable based on a hidden app toggle.
            const response = await post(aiHostnamePayload(name));
            submitted = true;
            if (response.run_service !== 'start_ai_request apply') throw new Error('Apply was not acknowledged');
            display(msg('設定已送出，正在等待 AI 板回報…', 'Request accepted; waiting for the AI board…'));
            for (let attempt = 0; attempt < 15; attempt++) {
                await new Promise(resolve => setTimeout(resolve, 2000));
                if (!input.isConnected) return;
                if (attempt % 5 === 0) await post({action_mode:'apply', rc_service:'start_ai_request query'});
                const status = await read();
                if (status.ai_hostname === name && status.ai_sys_hostname === name) {
                    savedName = name;
                    display(msg('AI 板已確認主機名稱：', 'AI board confirmed hostname: ') + name + '.local');
                    if (top.cachedData && typeof top.cachedData.clear === 'function') top.cachedData.clear(['ai_hostname','ai_sys_hostname']);
                    return;
                }
            }
            throw new Error('AI board did not confirm the hostname');
        } catch (_) {
            display(submitted ? msg('設定已送出，但尚未確認 AI 板已改名。請稍後重新整理核對；不要把此訊息當成成功。',
                                    'Request sent, but the AI board has not confirmed the change. Refresh later to check; success is not confirmed.')
                              : msg('無法完成主機名稱請求。請重新整理後核對設定。', 'Could not complete the hostname request. Refresh to check the settings.'));
        } finally {
            busy = false; input.disabled = false; update();
        }
    });
    update();
}
