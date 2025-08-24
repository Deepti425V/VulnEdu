document.addEventListener('DOMContentLoaded', function () {
    // === Pie Chart: Severity Distribution ===
    // Shows the distribution of CVEs by severity (Critical, High, Medium, Low)
    if (typeof metrics !== "undefined" &&
        document.getElementById('severityPie')) {
        // Create the chart using canvas context
        new Chart(document.getElementById('severityPie').getContext('2d'), {
            type: 'pie',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'], // Legend entries
                datasets: [{
                    data: [
                        metrics.critical || 0,
                        metrics.high || 0,
                        metrics.medium || 0,
                        metrics.low || 0
                    ], // Get counts for each severity, fallback to 0 for missing
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
                    legend: { position: 'bottom' } // Show legend below the pie
                }
            }
        });
    }

    // === Line Chart: CVE Trend Over Time ===
    // Line chart for published CVEs over time (monthly granularity)
    if (typeof timeline_data !== "undefined" &&
        document.getElementById('timelineChart')) {
        // Prepare X and Y data series
        const labels = Object.keys(timeline_data); // x-axis: months (e.g. '2022-05')
        const values = Object.values(timeline_data); // y-axis: counts per month
        // Render the line chart
        new Chart(document.getElementById('timelineChart').getContext('2d'), {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'CVEs Published', // Dataset label (hidden in legend)
                    data: values,
                    fill: false, // No area below the line
                    borderColor: '#0897e3', // Line color (blue)
                    backgroundColor: '#0897e3', // Data point color (blue)
                    tension: 0.15 // Curve the lines slightly
                }]
            },
            options: {
                plugins: {
                    legend: { display: false } // No legend (only one line)
                },
                scales: {
                    x: { title: { display: true, text: 'Month' } }, // x-axis label
                    y: { title: { display: true, text: 'Number of CVEs' },
                        beginAtZero: true } // y-axis label, force zero baseline
                }
            }
        });
    }

    // === Horizontal Bar: Top CWE Types ===
    // Horizontal bar for showing most common CWE types in the period
    if (typeof cwe_stats !== "undefined" && document.getElementById('cweBar'))
    {
        // Use CWE keys as labels, and counts as data
        const barLabels = Object.keys(cwe_stats); // y-axis: CWE codes/titles
        const barValues = Object.values(cwe_stats); // x-axis: CVE counts per CWE
        // Render the bar chart with horizontal bars
        new Chart(document.getElementById('cweBar').getContext('2d'), {
            type: 'bar',
            data: {
                labels: barLabels,
                datasets: [{
                    label: 'Count', // Not shown in legend (see options below)
                    data: barValues,
                    backgroundColor: '#985ff6' // Purple bars for all entries
                }]
            },
            options: {
                indexAxis: 'y', // Horizontal bars, not vertical
                plugins: {
                    legend: { display: false } // Hide legend for single series
                },
                scales: {
                    x: { title: { display: true, text: 'Number of CVEs' } }, // x-axis label
                    y: { title: { display: true, text: 'CWE' } } // y-axis label
                }
            }
        });
    }
});
