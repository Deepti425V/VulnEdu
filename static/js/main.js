// Wait for the DOM to load to ensure all elements exist
document.addEventListener('DOMContentLoaded', function() {

    // === Timeline Chart (CVEs per Month) ===
    // Get the canvas element by id
    const tctx = document.getElementById('timelineChart');
    if (tctx) {
        // Parse JSON data from 'data-timeline' attribute on the canvas
        // Expects an object like: { '2021-10': 42, ... }
        const timelineData = JSON.parse(tctx.getAttribute('data-timeline') || '{}');
        // Use months as x-axis labels
        const labels = Object.keys(timelineData);
        // Use CVE counts as data points
        const data = Object.values(timelineData);
        // Create a vertical bar chart for timeline view
        new Chart(tctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'CVEs by Month (Last 5 Years)',
                    data: data,
                    backgroundColor: 'rgba(54, 162, 235, 0.5)', // light blue bars
                    borderColor: 'rgba(54, 162, 235, 1)', // blue border
                    borderWidth: 1
                }]
            },
            options: {
                // Always begin y-axis at zero for clarity
                scales: { y: { beginAtZero: true } },
                plugins: { legend: { display: false } } // Hide legend (single data series)
            }
        });
    }

    // === CWE Chart (Frequencies) ===
    // Get the canvas element by id
    const cweCtx = document.getElementById('cweChart');
    if (cweCtx) {
        // Parse JSON object from 'data-cwe' attribute
        // Expects object: { 'CWE-79': 50, ... }
        const cweData = JSON.parse(cweCtx.getAttribute('data-cwe') || '{}');
        // CWE codes/titles are horizontal axis labels
        const cweLabels = Object.keys(cweData);
        // CWE counts are shown as bar lengths
        const cweCounts = Object.values(cweData);
        // Create a horizontal bar chart for CWE frequencies
        new Chart(cweCtx, {
            type: 'bar',
            data: {
                labels: cweLabels,
                datasets: [{
                    label: 'CWE Count',
                    data: cweCounts,
                    backgroundColor: 'rgba(255, 99, 132, 0.5)', // light red bars
                    borderColor: 'rgba(255, 99, 132, 1)', // red border
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y', // Horizontal bars for readability
                scales: { x: { beginAtZero: true } }, // x-axis always starts at zero
                plugins: { legend: { display: false } } // Hide legend, single series
            }
        });
    }
});
