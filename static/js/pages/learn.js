// Main initialization - wait for DOM to be fully loaded before setting up interactive features
document.addEventListener('DOMContentLoaded', function() {

    /* ============================================================
       1. STACKED BAR CHART (CWEs BY SEVERITY)
       ============================================================ */

    function renderSeverityChart(topN = 10) {
        if (!window.cweSeverityData || !document.getElementById('cweSeverityChart')) return;

        const ctx = document.getElementById('cweSeverityChart').getContext('2d');

        const labels = window.cweSeverityData.labels.slice(0, topN);
        const codes = window.cweSeverityData.indices.slice(0, topN);
        const data = window.cweSeverityData.data;

        const datasets = [
            { label: 'Critical', data: data.CRITICAL.slice(0, topN), backgroundColor: '#f55855' },
            { label: 'High', data: data.HIGH.slice(0, topN), backgroundColor: '#f8a541' },
            { label: 'Medium', data: data.MEDIUM.slice(0, topN), backgroundColor: '#3b8ded' },
            { label: 'Low', data: data.LOW.slice(0, topN), backgroundColor: '#42d392' }
        ];

        if (data.UNKNOWN) {
            datasets.push({
                label: 'Unknown',
                data: data.UNKNOWN.slice(0, topN),
                backgroundColor: '#6b7280'
            });
        }

        if (window.cweSeverityChart) {
            window.cweSeverityChart.destroy();
        }

        window.cweSeverityChart = new Chart(ctx, {
            type: 'bar',
            data: { labels, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: { display: true, text: `CWEs by Severity — Top ${topN}` }
                },
                scales: {
                    x: { stacked: true, ticks: { color: '#E9ECE8' } },
                    y: { stacked: true, beginAtZero: true, ticks: { color: '#E9ECE8' } }
                },
                onClick: (evt, activeEls) => {
                    if (activeEls.length > 0) {
                        const index = activeEls[0].index;
                        const cweCode = codes[index];
                        window.location.href = "/vulnerabilities?q=" + encodeURIComponent(cweCode);
                    }
                }
            }
        });
    }

    // Initialize Chart Default (Top 10)
    renderSeverityChart(10);

    // TopN Filter Dropdown
    const severityFilter = document.getElementById('cweSeverityFilter');
    if (severityFilter) {
        severityFilter.addEventListener('change', () =>
            renderSeverityChart(parseInt(severityFilter.value, 10))
        );
    }


    /* ============================================================
       2. UTILITY
       ============================================================ */

    function htmlEncode(text) {
        var el = document.createElement('div');
        el.innerText = text || '';
        return el.innerHTML;
    }


    /* ============================================================
       3. PANEL STATES (Loading / Error)
       ============================================================ */

    function showLoadingState(code) {
        document.getElementById('cweDetailPanel').innerHTML = `
            <div style="text-align: center; padding: 40px; color: #a9adc1;">
                <div style="font-size: 2rem; margin-bottom: 16px;">⏳</div>
                <div>Loading ${code} details from MITRE...</div>
                <div style="margin-top: 8px; font-size: 0.9em;">This may take a few seconds</div>
            </div>
        `;
    }

    function showErrorState(code, error) {
        document.getElementById('cweDetailPanel').innerHTML = `
            <div style="text-align: center; padding: 40px; color: #f47174;">
                <div style="font-size: 2rem; margin-bottom: 16px;">⚠</div>
                <div>Failed to load ${code} details</div>
                <div style="margin-top: 8px; font-size: 0.9em; color: #a9adc1;">
                    Error: ${htmlEncode(error)}
                </div>
                <div style="margin-top: 16px;">
                    <a href="https://cwe.mitre.org/data/definitions/${code.replace('CWE-','')}.html"
                       target="_blank"
                       style="color:#63a4ff;text-decoration:underline;">
                        View on MITRE website ➚
                    </a>
                </div>
            </div>
        `;
    }


    /* ============================================================
       4. FETCH + RENDER CWE DETAIL PANEL
       ============================================================ */

    async function fetchCweData(code) {
        const res = await fetch(`/api/cwe/${code}`);
        const json = await res.json();
        if (!json.success) throw new Error(json.error);
        return json.data;
    }

    async function renderDetail(code) {
        showLoadingState(code);

        try {
            const cweDict = window.learnCweDict || {};
            let entry = cweDict[code];

            if (!entry || !entry.description || entry.description.length < 50) {
                entry = await fetchCweData(code);
                window.learnCweDict[code] = entry;
            }

            document.getElementById('cweDetailPanel').innerHTML = `
                <h2 style="color:#63a4ff;margin-top:0;margin-bottom:12px;">${code}: ${htmlEncode(entry.name)}</h2>
                <div style="margin-bottom: 18px; color:#e2e8f2;">
                    <strong>Definition:</strong>
                    <div style="margin-top:8px;line-height:1.5;">${htmlEncode(entry.description)}</div>
                </div>
                <a href="https://cwe.mitre.org/data/definitions/${code.replace('CWE-','')}.html"
                   target="_blank"
                   style="color:#63a4ff;text-decoration:underline;">
                    View official CWE documentation ➚
                </a>
            `;
        } catch (err) {
            showErrorState(code, err.message);
        }
    }


    /* ============================================================
       5. LIST SELECTION + AUTOLOAD
       ============================================================ */

    function setupList(id) {
        const list = document.getElementById(id);
        if (!list) return;

        Array.from(list.children).forEach(li => {
            li.onclick = async function() {
                Array.from(list.children).forEach(el => {
                    el.style.background = '';
                    el.style.borderLeft = '4px solid transparent';
                    el.style.color = '#E9ECE8';
                });
                this.style.background = '#212d46';
                this.style.borderLeft = '4px solid #A8C7B5';
                this.style.color = '#A8C7B5';

                await renderDetail(this.dataset.cwe);
            };
        });

        if (list.children.length) {
            list.children[0].click();
        }
    }

    setupList('cweListColumn');
    setupList('cweListFull');


    /* ============================================================
       6. TOGGLE LIST MODE
       ============================================================ */

    const toggleBtn = document.getElementById('toggleShowAllCwe');
    if (toggleBtn) {
        toggleBtn.onclick = function() {
            let showingAll = this.innerText.includes('Show All') === false;

            document.getElementById('cweListColumn').style.display = showingAll ? '' : 'none';
            document.getElementById('cweListFull').style.display = showingAll ? 'none' : '';

            document.getElementById('cweListModeTip').innerText = showingAll ? '(Your Key Set)' : '(Full Catalog)';
            this.innerText = showingAll ? 'Show All CWEs' : 'Show Only Key CWEs';

            const list = showingAll ? document.getElementById('cweListColumn') : document.getElementById('cweListFull');
            if (list.children.length) list.children[0].click();
        };
    }

});
