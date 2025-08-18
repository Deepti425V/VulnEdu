document.addEventListener('DOMContentLoaded', function() {
    // === Timeline Chart ===
    // Bar chart: CVEs discovered per month, 
    // for the last 5 years (data is embedded as a JSON string in the element's attribute)
    const tctx = document.getElementById('timelineChart');
    if (tctx) {
        // Parse the 'data-timeline' attribute 
        // (should be an object: {month: count, ...})
        const timelineData = JSON.parse(tctx.getAttribute('data-timeline') || '{}');
        const labels = Object.keys(timelineData); // x-axis: months (e.g. '2021-10')
        const data = Object.values(timelineData); // y-axis: CVE count for each month
        new Chart(tctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'CVEs by Month (Last 5 Years)',
                    data: data,
                    backgroundColor: 'rgba(54, 162, 235, 0.5)', // soft blue bars
                    borderColor: 'rgba(54, 162, 235, 1)', // sharper blue borders
                    borderWidth: 1
                }]
            },
            options: {
                scales: { y: { beginAtZero: true } }, // y-axis always starts at zero
                plugins: { legend: { display: false } }  // hide the legend (single series)
            }
        });
    }

    // === CWE Chart ===
    // Horizontal bar chart of CWE type frequencies 
    // (data is also embedded as JSON in attribute)
    const cweCtx = document.getElementById('cweChart');
    if (cweCtx) {
        // Parse the 'data-cwe' attribute 
        // (should be { CWE-79: count, CWE-89: count, ... })
        const cweData = JSON.parse(cweCtx.getAttribute('data-cwe') || '{}');
        const cweLabels = Object.keys(cweData); // y-axis: CWE code/title
        const cweCounts = Object.values(cweData); // x-axis: count for each CWE
        new Chart(cweCtx, {
            type: 'bar',
            data: {
                labels: cweLabels,
                datasets: [{
                    label: 'CWE Count',
                    data: cweCounts,
                    backgroundColor: 'rgba(255, 99, 132, 0.5)', // soft red bars
                    borderColor: 'rgba(255, 99, 132, 1)', // red borders
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y', // horizontal bars
                scales: { x: { beginAtZero: true } }, // x-axis starts at zero
                plugins: { legend: { display: false } }  // hide legend (single series)
            }
        });
    }
});
