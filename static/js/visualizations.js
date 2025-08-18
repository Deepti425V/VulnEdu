document.addEventListener('DOMContentLoaded', function () {
    // === Pie Chart: Severity Distribution ===
    // Shows the distribution of CVEs by severity 
    // (Critical, High, Medium, Low)
    if (typeof metrics !== "undefined" && document.getElementById('severityPie')) {
        new Chart(document.getElementById('severityPie').getContext('2d'), {
            type: 'pie',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        metrics.critical || 0,
                        metrics.high || 0,
                        metrics.medium || 0,
                        metrics.low || 0
                    ], // grab counts (fallback to 0 if missing)
                    backgroundColor: [
                        '#e74c3c', // Critical (red)
                        '#f1c40f', // High (yellow/gold)
                        '#985ff6', // Medium (purple)
                        '#24d18c'  // Low (green)
                    ]
                }]
            },
            options: {
                plugins: {
                    legend: { position: 'bottom' } // show legend under the pie
                }
            }
        });
    }

    // === Line Chart: CVE Trend Over Time ===
    // Line chart for published CVEs over time (monthly granularity)
    if (typeof timeline_data !== "undefined" && document.getElementById('timelineChart')) {
        const labels = Object.keys(timeline_data);  // x-axis: months
        const values = Object.values(timeline_data); // y-axis: counts
        new Chart(document.getElementById('timelineChart').getContext('2d'), {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'CVEs Published', // Chart legend label (hidden per options)
                    data: values,
                    fill: false, // line only (no fill underneath)
                    borderColor: '#0897e3', // blue line
                    backgroundColor: '#0897e3',  // slight curve to lines
                    tension: 0.15
                }]
            },
            options: {
                plugins: {
                    legend: { display: false } // no legend needed (single dataset)
                },
                scales: {
                    x: { title: { display: true, text: 'Month' } },
                    y: { title: { display: true, text: 'Number of CVEs' }, beginAtZero: true } // y-label, always starts at zero
                }
            }
        });
    }

    // === Horizontal Bar: Top CWE Types ===
    // Horizontal bar chart for showing most common CWE types in the period
    if (typeof cwe_stats !== "undefined" && document.getElementById('cweBar')) {
        const barLabels = Object.keys(cwe_stats); // y-axis: CWE code/title
        const barValues = Object.values(cwe_stats); // x-axis: count for each type
        new Chart(document.getElementById('cweBar').getContext('2d'), {
            type: 'bar',
            data: {
                labels: barLabels,
                datasets: [{
                    label: 'Count', // not shown (hidden legend)
                    data: barValues,
                    backgroundColor: '#985ff6' // purple bars for all
                }]
            },
            options: {
                indexAxis: 'y', // horizontal bars
                plugins: {
                    legend: { display: false } // keep legend off for clarity
                },
                scales: {
                    x: { title: { display: true, text: 'Number of CVEs' } }, // x-label
                    y: { title: { display: true, text: 'CWE' } } // y-label
                }
            }
        });
    }
});
