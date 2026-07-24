const el = (selector) => document.querySelector(selector);
let findings = [], activeFilter = 'all';
const list = el('#findingList'), empty = el('#empty');

function escape(value) { const d = document.createElement('div'); d.textContent = value; return d.innerHTML; }
function updateProgress(step, target, percent = 0) {
  const label = el('#scanProgressLabel');
  const bar = el('#scanProgressBar');
  const currentTarget = el('#scanTarget');
  if (!label || !bar || !currentTarget) return;
  const steps = {
    idle: { label: 'Ready', percent: 0 },
    uploading: { label: 'Uploading', percent: 25 },
    scanning: { label: 'Scanning', percent: 65 },
    complete: { label: 'Finished', percent: 100 },
    failed: { label: 'Scan failed', percent: 0 },
  };
  const state = steps[step] || steps.idle;
  label.textContent = state.label;
  currentTarget.textContent = target || 'No active scan';
  bar.style.width = `${Math.max(0, Math.min(100, percent || state.percent))}%`;
}
function canAutoRemediate(finding) {
  const supported = /\.(py|js|mjs|cjs|ts|tsx|jsx)$/i.test((finding.file || '').toString());
  const isWorkingTree = finding.source === 'working tree';
  return Boolean(finding.remediable) && supported && isWorkingTree && finding.rule !== 'private_key';
}
function render() {
  const shown = findings.filter(f => activeFilter === 'all' || (activeFilter === 'history' ? f.source === 'git history' : f.severity === activeFilter));
  list.innerHTML = shown.map(f => `<article class="finding ${f.severity}" data-id="${f.id}">
    <div><div class="finding-head"><span class="badge ${f.severity}">${f.severity}</span><h3>${escape(f.description)}</h3>${f.source === 'git history' ? '<span class="history-pill">GIT HISTORY</span>' : ''}</div>
    <div class="meta">${escape(f.file)}:${f.line}${f.commit ? ` · commit ${f.commit}` : ''} · ${escape(f.category)} · ${f.confidence} confidence</div>
    <code class="secret">${escape(f.match)}</code><p class="blast"><b>Blast radius:</b> ${escape(f.blast_radius)}</p></div>
    <div class="actions"><button class="action" data-review="${f.id}">Review with AI</button>${canAutoRemediate(f) ? `<button class="action primary" data-fix="${f.id}">Auto-remediate</button>` : '<span class="manual-label">Manual fix</span>'}<button class="action" data-instructions="${f.id}">How to fix</button></div>
  </article>`).join('');
  empty.style.display = findings.length || activeFilter !== 'all' ? 'none' : 'block';
  if (!shown.length && findings.length) list.innerHTML = '<div class="empty"><h3>No matching findings</h3><p>Try another filter.</p></div>';
}
function toast(message) { const box = el('#toast'); box.textContent = message; box.classList.add('show'); setTimeout(() => box.classList.remove('show'), 4800); }
async function post(url, body) { const res = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}); return res.json(); }
async function scan() {
  const button = el('#scanBtn'), status = el('#status'); button.disabled = true; button.innerHTML = '<span>↻</span> Scanning…'; status.classList.add('loading'); status.innerHTML = '<i></i> Inspecting your project…';
  updateProgress('scanning', 'Current workspace', 20);
  try { const data = await post('/api/scan', {history:el('#history').checked}); findings = data.findings; el('#projectName').textContent = data.root; ['critical','high','medium','low'].forEach(k => el('#'+k).textContent = data.counts[k]); el('#navCount').textContent = findings.length; status.innerHTML = `<i></i> Scan complete · ${findings.length} finding${findings.length === 1 ? '' : 's'}`; updateProgress('complete', data.root || 'Current workspace', 100); render(); }
  catch { status.innerHTML = '<i></i> Scan failed'; updateProgress('failed', 'Current workspace', 0); toast('The scan could not finish. Make sure the local server is running.'); }
  finally { button.disabled = false; button.innerHTML = '<span>↻</span> Run scan'; status.classList.remove('loading'); }
}
async function scanUpload(file) {
  if (!file) return;
  if (file.size > 1_500_000) return toast('Please choose a text file smaller than 1.5 MB.');
  const button = el('#uploadBtn'), status = el('#status'); button.disabled = true; button.textContent = 'Reading…'; status.classList.add('loading'); status.innerHTML = '<i></i> Preparing upload…';
  updateProgress('uploading', file.name, 20);
  try { const content = await file.text(); updateProgress('scanning', file.name, 65); const data = await post('/api/scan-upload', {name:file.name, content}); if (data.error) throw new Error(data.error); findings = data.findings; el('#projectName').textContent = file.name; ['critical','high','medium','low'].forEach(k => el('#'+k).textContent = data.counts[k]); el('#navCount').textContent = findings.length; status.innerHTML = `<i></i> File scan complete · ${findings.length} finding${findings.length === 1 ? '' : 's'}`; updateProgress('complete', file.name, 100); render(); }
  catch (error) { status.innerHTML = '<i></i> File scan failed'; updateProgress('failed', file.name, 0); toast(error.message || 'Could not read that file.'); }
  finally { button.disabled = false; button.textContent = 'Scan a file'; status.classList.remove('loading'); el('#fileInput').value = ''; }
}
async function scanRepo() {
  const repoUrl = el('#repoInput').value.trim();
  if (!repoUrl) return toast('Enter a Git repository URL.');
  const button = el('#repoScanBtn'), status = el('#status'); button.disabled = true; button.textContent = 'Scanning…'; status.classList.add('loading'); status.innerHTML = '<i></i> Cloning repository…';
  updateProgress('uploading', repoUrl, 20);
  try {
    const data = await post('/api/scan-repo', {repo: repoUrl, history: el('#history').checked});
    if (data.error) throw new Error(data.error);
    findings = data.findings;
    el('#projectName').textContent = repoUrl;
    ['critical','high','medium','low'].forEach(k => el('#'+k).textContent = data.counts[k]);
    el('#navCount').textContent = findings.length;
    status.innerHTML = `<i></i> Scan complete · ${findings.length} finding${findings.length === 1 ? '' : 's'}`;
    updateProgress('complete', repoUrl, 100);
    render();
  } catch (error) {
    status.innerHTML = '<i></i> Scan failed';
    updateProgress('failed', repoUrl, 0);
    toast(error.message || 'Could not scan that repository.');
  } finally {
    button.disabled = false;
    button.textContent = 'Scan Git repo';
    status.classList.remove('loading');
  }
}
list.addEventListener('click', async (event) => {
  const review = event.target.dataset.review, fix = event.target.dataset.fix, guide = event.target.dataset.instructions;
  if (review) { event.target.disabled = true; event.target.textContent = 'Reviewing…'; const data = await post('/api/review', {id:review}); const card = event.target.closest('.finding'); card.querySelector('.review')?.remove(); card.insertAdjacentHTML('beforeend', `<div class="review"><b>${escape(data.verdict || 'review')}:</b> ${escape(data.reason || data.error)} <span>· ${escape(data.reviewer || '')}</span></div>`); event.target.textContent = 'AI review'; event.target.disabled = false; }
  if (fix) { event.target.disabled = true; const data = await post('/api/remediate', {id:fix}); toast(data.message); if (data.ok) { findings = findings.filter(f => f.id !== fix); el('#navCount').textContent = findings.length; render(); } else event.target.disabled = false; }
  if (guide) { event.target.disabled = true; const data = await post('/api/instructions', {id:guide}); const card = event.target.closest('.finding'); card.querySelector('.instructions')?.remove(); const items = (data.steps || [data.error]).map(step => `<li>${escape(step)}</li>`).join(''); card.insertAdjacentHTML('beforeend', `<div class="review instructions"><b>${escape(data.title || 'How to fix')}</b><ol>${items}</ol></div>`); event.target.disabled = false; }
});
document.querySelectorAll('.filter').forEach(button => button.addEventListener('click', () => { document.querySelector('.filter.selected').classList.remove('selected'); button.classList.add('selected'); activeFilter = button.dataset.filter; render(); }));
el('#scanBtn').addEventListener('click', scan);
el('#repoScanBtn').addEventListener('click', scanRepo);
const pathInputEl = el('#pathInput');
const pathScanBtnEl = el('#pathScanBtn');
if (pathScanBtnEl) pathScanBtnEl.addEventListener('click', scanPath);
el('#uploadBtn').addEventListener('click', () => el('#fileInput').click());
el('#fileInput').addEventListener('change', event => scanUpload(event.target.files[0]));
const pickFolderBtnEl = el('#pickFolderBtn');
if (pickFolderBtnEl) pickFolderBtnEl.addEventListener('click', pickFolder);

async function scanPath() {
  const pathVal = (pathInputEl && pathInputEl.value || '').trim();
  if (!pathVal) return toast('Enter a local folder path.');
  const button = pathScanBtnEl, status = el('#status');
  if (button) { button.disabled = true; button.textContent = 'Scanning…'; }
  status.classList.add('loading'); status.innerHTML = '<i></i> Scanning local folder…';
  updateProgress('uploading', pathVal, 20);
  try {
    const data = await post('/api/scan-path', {path: pathVal, history: el('#history').checked});
    if (data.error) throw new Error(data.error);
    findings = data.findings;
    el('#projectName').textContent = pathVal;
    ['critical','high','medium','low'].forEach(k => el('#'+k).textContent = data.counts[k]);
    el('#navCount').textContent = findings.length;
    status.innerHTML = `<i></i> Scan complete · ${findings.length} finding${findings.length === 1 ? '' : 's'}`;
    updateProgress('complete', pathVal, 100);
    render();
  } catch (error) {
    status.innerHTML = '<i></i> Scan failed';
    updateProgress('failed', pathVal, 0);
    toast(error.message || 'Could not scan that folder.');
  } finally {
    if (button) { button.disabled = false; button.textContent = 'Scan folder'; }
    status.classList.remove('loading');
  }
}

async function pickFolder() {
  if (!window.showDirectoryPicker) return toast('Directory picker not supported in this browser. Try Chrome or Edge.');
  const button = pickFolderBtnEl, status = el('#status');
  if (button) { button.disabled = true; button.textContent = 'Picking…'; }
  status.classList.add('loading'); status.innerHTML = '<i></i> Opening folder chooser…';
  updateProgress('uploading', 'Choose folder', 10);
  try {
    const dirHandle = await window.showDirectoryPicker();
    const files = [];
    async function traverse(handle, base) {
      for await (const entry of handle.values()) {
        if (entry.kind === 'file') {
          try {
            const f = await entry.getFile();
            if (f.size > 1_500_000) continue;
            const content = await f.text();
            const rel = base ? `${base}/${entry.name}` : entry.name;
            files.push({ name: rel, content });
          } catch (err) { /* skip unreadable files */ }
        } else if (entry.kind === 'directory') {
          await traverse(entry, base ? `${base}/${entry.name}` : entry.name);
        }
      }
    }
    await traverse(dirHandle, '');
    if (!files.length) { toast('No readable files found in that folder.'); updateProgress('failed', dirHandle.name, 0); return; }
    updateProgress('scanning', dirHandle.name, 30);
    const aggregated = [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    let processed = 0;
    for (const f of files) {
      updateProgress('scanning', f.name, 30 + Math.round((processed / files.length) * 60));
      const data = await post('/api/scan-upload', { name: f.name, content: f.content });
      if (data && data.findings) aggregated.push(...data.findings);
      if (data && data.counts) Object.keys(counts).forEach(k => counts[k] += (data.counts[k] || 0));
      processed += 1;
    }
    findings = aggregated;
    el('#projectName').textContent = dirHandle.name;
    ['critical','high','medium','low'].forEach(k => el('#'+k).textContent = counts[k]);
    el('#navCount').textContent = findings.length;
    updateProgress('complete', dirHandle.name, 100);
    render();
  } catch (error) {
    toast(error.message || 'Folder selection cancelled or failed.');
    updateProgress('failed', 'Folder', 0);
  } finally {
    if (button) { button.disabled = false; button.textContent = 'Pick folder'; }
    status.classList.remove('loading');
  }
}
