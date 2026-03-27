<!doctype html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Navigator Pro | Visual Studio Security</title>
    <script src="https://cdn.tailwindcss.com/3.4.17"></script>
    <script src="https://cdn.jsdelivr.net/npm/lucide@0.263.0/dist/umd/lucide.min.js"></script>
    <script src="/_sdk/element_sdk.js"></script>
    <script src="/_sdk/data_sdk.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        html, body { height: 100%; margin: 0; background: #0a0e1a; color: #f0f0f0; font-family: 'DM Sans', sans-serif; }
        .glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.08); }
        .card { background: rgba(15,20,35,0.8); border: 1px solid rgba(74,222,128,0.15); border-radius: 12px; }
        .btn-primary { background: linear-gradient(135deg, #1a5c3a 0%, #2a7a4a 100%); border: 1px solid rgba(74,222,128,0.3); transition: all 0.3s; }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(26,92,58,0.4); border-color: #4ade80; }
        .severity-critical { color: #ef4444; background: rgba(239,68,68,0.1); }
        .severity-high { color: #f97316; background: rgba(249,115,22,0.1); }
        .fade-in { animation: fadeIn 0.6s ease both; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body class="h-full">
    <div id="app" class="w-full h-full overflow-auto flex flex-col">
        <header class="fade-in px-6 py-4 border-b border-white/10 sticky top-0 z-50" style="background: rgba(10, 14, 26, 0.8);">
            <div class="flex items-center justify-between flex-wrap gap-4">
                <div class="flex items-center gap-3">
                    <div class="w-12 h-12 rounded-lg flex items-center justify-center bg-gradient-to-br from-green-600 to-green-800">
                        <i data-lucide="shield-check" style="width:24px;height:24px;color:#fff;"></i>
                    </div>
                    <div>
                        <h1 class="text-xl font-bold text-white">Visual Studio Security</h1>
                        <p class="text-xs text-gray-400">Advanced Cyber Audit Engine</p>
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    <button id="newScanBtn" onclick="showScanModal()" class="btn-primary text-white px-6 py-2 rounded-lg font-medium flex items-center gap-2">
                        <i data-lucide="zap" style="width:18px;height:18px;"></i> New Scan
                    </button>
                </div>
            </div>
        </header>

        <main class="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="card p-6">
                    <span class="text-sm text-gray-400">Total Audits</span>
                    <p class="text-3xl font-bold text-white" id="statTotalScans">0</p>
                </div>
                <div class="card p-6 border-red-500/20">
                    <span class="text-sm text-gray-400">Vulnerabilities Found</span>
                    <p class="text-3xl font-bold text-red-400" id="statVulnerabilities">0</p>
                </div>
                <div class="card p-6 border-blue-500/20">
                    <span class="text-sm text-gray-400">Engine Status</span>
                    <p class="text-3xl font-bold text-green-400">ONLINE</p>
                </div>
            </div>

            <section class="card overflow-hidden">
                <div class="p-4 border-b border-white/10 flex justify-between items-center">
                    <h2 class="font-bold">Recent Scans</h2>
                    <button onclick="updateDashboard()" class="text-xs text-gray-400 hover:text-white flex items-center gap-1">
                        <i data-lucide="refresh-cw" style="width:12px;"></i> Refresh
                    </button>
                </div>
                <table class="w-full text-sm text-left">
                    <thead class="text-gray-400 bg-white/5">
                        <tr>
                            <th class="p-4">Target URL</th>
                            <th class="p-4">Type</th>
                            <th class="p-4">Issues</th>
                            <th class="p-4">Date</th>
                            <th class="p-4">Status</th>
                        </tr>
                    </thead>
                    <tbody id="scansTableBody">
                        <tr><td colspan="5" class="p-10 text-center text-gray-500">No scans performed yet.</td></tr>
                    </tbody>
                </table>
            </section>
        </main>

        <div id="scanModal" class="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-[100]" style="display: none;">
            <div class="card p-6 w-full max-w-md">
                <h2 class="text-lg font-bold mb-4 text-white">Configure New Audit</h2>
                <div class="space-y-4">
                    <input type="url" id="scanUrl" class="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-2 text-white outline-none focus:border-green-500" placeholder="https://target-site.com">
                    <select id="scanType" class="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-2 text-white outline-none">
                        <option value="basic">Standard Web Scan</option>
                        <option value="full">Deep Infrastructure Audit</option>
                    </select>
                    <div class="flex gap-2">
                        <button onclick="closeScanModal()" class="flex-1 py-2 bg-white/5 rounded-lg">Cancel</button>
                        <button onclick="executeScan()" class="flex-1 btn-primary py-2 rounded-lg text-white font-bold">Launch Scan</button>
                    </div>
                </div>
            </div>
        </div>

        <div id="toast" class="fixed bottom-6 right-6 bg-black border border-green-500/50 p-4 rounded-lg shadow-2xl z-[200]" style="display: none;">
            <p id="toastMessage" class="text-sm text-green-400 font-mono"></p>
        </div>
    </div>

    <script>
        // --- 1. CONFIGURAÇÃO DATA SDK & DASHBOARD ---
        let scanData = [];

        async function initDataSDK() {
            const result = await window.dataSdk.init({
                onDataChanged: (data) => {
                    scanData = data;
                    updateDashboard();
                }
            });
        }
        initDataSDK();

        function updateDashboard() {
            const tableBody = document.getElementById('scansTableBody');
            const totalScans = document.getElementById('statTotalScans');
            const totalVulns = document.getElementById('statVulnerabilities');

            if (!scanData || scanData.length === 0) return;

            totalScans.textContent = scanData.length;
            let sumVulns = 0;

            tableBody.innerHTML = scanData.map(scan => {
                sumVulns += (scan.vulnerabilityCount || 0);
                return `
                    <tr class="border-t border-white/5 hover:bg-white/5">
                        <td class="p-4 text-gray-300 font-mono text-xs">${scan.url}</td>
                        <td class="p-4 capitalize">${scan.scanType}</td>
                        <td class="p-4"><span class="px-2 py-1 rounded ${scan.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'} text-xs font-bold">${scan.vulnerabilityCount} Issues</span></td>
                        <td class="p-4 text-xs text-gray-500">${new Date(scan.createdAt).toLocaleDateString()}</td>
                        <td class="p-4 text-green-400 text-xs font-bold">READY</td>
                    </tr>`;
            }).reverse().join('');

            totalVulns.textContent = sumVulns;
        }

        // --- 2. INTEGRAÇÃO REAL COM O MOTOR PYTHON (BACKEND) ---
        async function executeScan() {
            const urlInput = document.getElementById('scanUrl').value;
            const scanType = document.getElementById('scanType').value;

            if (!urlInput.startsWith('http')) {
                showToast("Erro: Use a URL completa (http/https)");
                return;
            }

            showToast("ENGINE: Iniciando Auditoria...");
            closeScanModal();

            try {
                const response = await fetch('http://127.0.0.1:8000/api/v1/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: urlInput })
                });

                const data = await response.json();
                
                const newScan = {
                    url: data.url,
                    scanType: scanType,
                    status: 'completed',
                    vulnerabilityCount: data.vulnerabilities.length,
                    severity: data.vulnerabilities.some(v => v.severity === 'critical') ? 'critical' : 'high',
                    createdAt: new Date().toISOString()
                };

                await window.dataSdk.create(newScan);
                showToast(`SUCCESS: ${data.vulnerabilities.length} falhas detectadas.`);
            } catch (e) {
                showToast("ERROR: Backend Python Offline!");
            }
        }

        // --- 3. SCRIPT DE PROTEÇÃO "BLOQUEIO HACKER" (ANTI-F12) ---
        const activateBlock = () => {
            document.body.innerHTML = `
                <div style="background:#050505;color:#f00;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:'Space Mono',monospace;text-align:center;padding:20px;">
                    <h1 style="font-size:2.5rem;text-shadow:0 0 15px #f00;">ACCESS DENIED</h1>
                    <p style="margin:20px 0;font-size:1.1rem;color:#888;">Tentativa de interceptação detectada pela Visual Studio Security.</p>
                    <div style="border:1px solid #333;padding:20px;background:#0a0a0a;color:#555;font-size:0.8rem;">
                        [THREAD_PROTECTION_ACTIVED]<br>
                        LOG: FAUX#ELEVATE_DETECTION_ID_${Math.floor(Math.random()*99999)}<br>
                        STATUS: IP_LOGGED_AND_SHIELDED
                    </div>
                    <button onclick="location.reload()" style="margin-top:30px;background:#f00;color:#fff;padding:12px 30px;border:none;cursor:pointer;font-weight:bold;letter-spacing:2px;">RECONECTAR</button>
                </div>`;
        };

        window.addEventListener('keydown', (e) => {
            if (e.key === "F12" || (e.ctrlKey && e.shiftKey && (e.key === "I" || e.key === "J" || e.key === "C")) || (e.ctrlKey && e.key === "U")) {
                e.preventDefault();
                activateBlock();
            }
        });

        // --- UI HELPERS ---
        function showScanModal() { document.getElementById('scanModal').style.display = 'flex'; }
        function closeScanModal() { document.getElementById('scanModal').style.display = 'none'; }
        function showToast(msg) {
            const t = document.getElementById('toast');
            document.getElementById('toastMessage').textContent = msg;
            t.style.display = 'block';
            setTimeout(() => t.style.display = 'none', 4000);
        }
        lucide.createIcons();
    </script>
</body>
</html>
