async function api(path, options = {}) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail));
  return data;
}
function dashboard() {
  return {
    target: '', pages: 10, scans: [], selected: null, logs: [], connected: false,
    error: '', busy: false, count: 0, detail: '', elements: null,
    get visibleLogs() { return this.logs.filter(l => !this.selected || l.scan_id === this.selected); },
    async init() {
      if (typeof cytoscape === 'undefined') { this.error = 'Cytoscape failed to load. Check access to the CDN.'; return; }
      window.specterGraph = cytoscape({ container: document.getElementById('graph'), elements: [], style: [
        { selector: 'node', style: { label: 'data(label)', 'font-size': 10, color: '#94a3b8', 'text-valign': 'bottom', 'text-margin-y': 8, 'text-max-width': 140, 'text-wrap': 'ellipsis', 'background-color': '#38bdf8', width: 24, height: 24 } },
        { selector: 'node[kind="domain"]', style: { 'background-color': '#34d399', width: 42, height: 42 } },
        { selector: 'node[kind="cve"]', style: { 'background-color': '#fb7185', shape: 'diamond' } },
        { selector: 'node[kind="service"]', style: { 'background-color': '#c084fc' } },
        { selector: 'edge', style: { width: 1, 'line-color': '#334155', 'target-arrow-color': '#475569', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier' } },
        { selector: ':selected', style: { 'border-width': 3, 'border-color': '#fff' } }
      ] });
      window.specterGraph.on('tap', 'node', e => { this.detail = JSON.stringify(e.target.data(), null, 2); });
      await this.refresh();
      if (this.scans.length) await this.select(this.scans[0].id);
      this.connect();
      setInterval(() => this.refresh(), 2500);
    },
    async refresh() {
      try {
        const old = this.scans.find(s => s.id === this.selected)?.status;
        this.scans = await api('/api/scans');
        const current = this.scans.find(s => s.id === this.selected);
        if (current?.status === 'completed' && old !== 'completed') await this.select(this.selected);
      } catch (e) { this.error = e.message; }
    },
    async start() {
      this.busy = true; this.error = '';
      try {
        const scan = await api('/api/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: this.target, max_pages: this.pages }) });
        await this.refresh(); await this.select(scan.id);
      } catch (e) { this.error = e.message; } finally { this.busy = false; }
    },
    async select(id) {
      this.selected = id; this.detail = '';
      try {
        const elements = await api(`/api/scans/${id}/graph`);
        if (this.selected !== id) return;
        this.elements = elements; this.count = elements.nodes.length;
        window.specterGraph.elements().remove(); window.specterGraph.add(elements);
        window.specterGraph.layout({ name: 'cose', animate: false, padding: 40 }).run();
      } catch (e) { this.error = e.message; }
    },
    async cancel(id) {
      try { await api(`/api/scans/${id}/cancel`, { method: 'POST' }); await this.refresh(); }
      catch (e) { this.error = e.message; }
    },
    connect() {
      const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/logs`);
      socket.onopen = () => { this.connected = true; this.logs = []; };
      socket.onmessage = e => {
        const log = JSON.parse(e.data); if (log.type === 'heartbeat') return;
        this.logs.push(log); if (this.logs.length > 300) this.logs.shift();
        this.$nextTick(() => { const box = document.getElementById('logs'); box.scrollTop = box.scrollHeight; });
      };
      socket.onclose = () => { this.connected = false; setTimeout(() => this.connect(), 2000); };
      socket.onerror = () => socket.close();
    },
    download() {
      const url = URL.createObjectURL(new Blob([JSON.stringify(this.elements, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a'); link.href = url; link.download = `spectermap-${this.selected}.json`; link.click(); URL.revokeObjectURL(url);
    }
  };
}
