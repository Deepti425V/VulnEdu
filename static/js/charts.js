// Run only after HTML document has fully loaded
document.addEventListener('DOMContentLoaded', function() {

    // Ensure vulnerability metrics data from backend is available
    if (typeof metricsData !== 'undefined') {

        // === Severity Pie Chart ===
        const severityCtx = document.getElementById('severityPie');
        if (severityCtx) {
            new Chart(severityCtx, {
                type: 'pie', // simple pie chart for severity categories
                data: {
                    // Labels for severity levels
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        // Values pulled from global metricsData
                        data: [
                            metricsData.severity.critical,
                            metricsData.severity.high,
                            metricsData.severity.medium,
                            metricsData.severity.low
                        ],
                        backgroundColor: [
                            '#f94144', // Critical - red
                            '#f8961e', // High - orange
                            '#43aa8b', // Medium - green
                            '#90be6d'  // Low - light green
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right' // place legends outside for readability
                        },
                        title: {
                            display: true,
                            text: 'Severity Distribution'
                        }
                    }
                }
            });
        }

        // === CWE Bar Chart ===
        if (metricsData.cweStats && Object.keys(metricsData.cweStats).length > 0) {
            const cweCtx = document.getElementById('cweBar');
            if (cweCtx) {
                // Extract CWE names & counts from dataset
                const cweLabels = Object.keys(metricsData.cweStats);
                const cweData = Object.values(metricsData.cweStats);

                new Chart(cweCtx, {
                    type: 'bar', // default vertical, but changed via indexAxis
                    data: {
                        labels: cweLabels,
                        datasets: [{
                            label: 'Count',
                            data: cweData,
                            backgroundColor: '#4361ee', // consistent blue color
                            borderWidth: 1
                        }]
                    },
                    options: {
                        indexAxis: 'y', // horizontal orientation improves readability
                        responsive: true,
                        plugins: {
                            legend: {
                                display: false // no legend, single dataset only
                            },
                            title: {
                                display: true,
                                text: 'Top Vulnerability Types'
                            }
                        },
                        scales: {
                            x: {
                                beginAtZero: true // X-axis starts at 0 for counts
                            }
                        }
                    }
                });
            }
        }

        // === CWE by Severity Stacked Bar Chart ===
        if (metricsData.cweSeverity && Object.keys(metricsData.cweSeverity).length > 0) {

            // Try to get existing canvas element
            const severityTrendCtx = document.getElementById('severityTrendChart');
            
            // If not found, create canvas dynamically
            if (!severityTrendCtx) {
                const trendParent = document.getElementById('trendChart');
                if (trendParent) {
                    const newCanvas = document.createElement('canvas');
                    newCanvas.id = 'severityTrendChart';
                    trendParent.parentNode.appendChild(newCanvas);
                }
            }

            // Now retrieve final canvas reference
            const severityCtx = document.getElementById('severityTrendChart');
            if (severityCtx) {
                const cweLabels = Object.keys(metricsData.cweSeverity);

                // Severities handled in consistent order (critical → low)
                const severityLevels = ['critical', 'high', 'medium', 'low'];
                const colors = ['#f94144', '#f8961e', '#43aa8b', '#90be6d'];

                // Build one dataset per severity level
                const datasets = severityLevels.map((sev, i) => ({
                    label: sev.charAt(0).toUpperCase() + sev.slice(1),
                    data: cweLabels.map(cwe => metricsData.cweSeverity[cwe][sev] || 0),
                    backgroundColor: colors[i]
                }));

                new Chart(severityCtx, {
                    type: 'bar',
                    data: {
                        labels: cweLabels,
                        datasets: datasets
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Vulnerability Types by Severity'
                            }
                        },
                        scales: {
                            x: { stacked: true }, // stack severities side by side
                            y: { stacked: true }  // enable vertical stacking
                        }
                    }
                });
            }
        }
    }
});
