document.addEventListener('DOMContentLoaded', function() 
{
    //Grab stats & metrics
    if (typeof metricsData !== 'undefined') 
        {
        // === Severity Pie Chart ===
        const severityCtx = document.getElementById('severityPie');
        if (severityCtx) {
            new Chart(severityCtx, {
                type: 'pie',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],  //severity buckets we care about
                    datasets: [{
                        data: [
                            metricsData.severity.critical,
                            metricsData.severity.high,
                            metricsData.severity.medium,
                            metricsData.severity.low
                        ], //matches labels above, in order
                        backgroundColor: [
                            '#f94144', //critical-red
                            '#f8961e', //high-orange
                            '#43aa8b', //medium-green
                            '#90be6d'  //low-light-green
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right' //keep legend beside pie for quick reading
                        },
                        title: {
                            display: true,
                            text: 'Severity Distribution' //dashboard headline
                        }
                    }
                }
            });
        }

        // === CWE Bar Chart ===
        if (metricsData.cweStats && Object.keys(metricsData.cweStats).length > 0) {
            const cweCtx = document.getElementById('cweBar');
            if (cweCtx) {
                const cweLabels = Object.keys(metricsData.cweStats); // CWE names/codes
                const cweData = Object.values(metricsData.cweStats); // their counts
                
                new Chart(cweCtx, {
                    type: 'bar',
                    data: {
                        labels: cweLabels, //bar labels = CWE types
                        datasets: [{
                            label: 'Count', //count of each type
                            data: cweData,
                            backgroundColor: '#4361ee', //unified color for bars
                            borderWidth: 1
                        }]
                    },
                    options: {
                        indexAxis: 'y', //horizontal bars (easier for wide lists)
                        responsive: true,
                        plugins: {
                            legend: {
                                display: false //don't show legend (single dataset)
                            },
                            title: {
                                display: true,
                                text: 'Top Vulnerability Types' //dashboard headline
                            }
                        },
                        scales: {
                            x: {
                                beginAtZero: true //bar count always starts at 0
                            }
                        }
                    }
                });
            }
        }

        // === CWE by Severity Stacked Bar Chart ===
        if (metricsData.cweSeverity && Object.keys(metricsData.cweSeverity).length > 0) {
            const severityTrendCtx = document.getElementById('severityTrendChart');
            if (!severityTrendCtx) {
                //If the canvas doesn't exist, add it into the DOM
                const trendParent = document.getElementById('trendChart');
                if (trendParent) {
                    const newCanvas = document.createElement('canvas');
                    newCanvas.id = 'severityTrendChart';
                    trendParent.parentNode.appendChild(newCanvas);
                }
            }

            //Now fetch actual canvas we want to chart onto
            const severityCtx = document.getElementById('severityTrendChart');
            if (severityCtx) {
                const cweLabels = Object.keys(metricsData.cweSeverity); //CWE types/codes
                const severityLevels = ['critical', 'high', 'medium', 'low'];  //order matters for stacks
                const colors = ['#f94144', '#f8961e', '#43aa8b', '#90be6d']; //matching pie chart colors

                // Build the severity breakdown for each CWE (one dataset per severity level)
                const datasets = severityLevels.map((sev, i) => ({
                    label: sev.charAt(0).toUpperCase() + sev.slice(1), //"Critical", "High", "Meidum", "Low".
                    data: cweLabels.map(cwe => metricsData.cweSeverity[cwe][sev] || 0), //value for each cwe
                    backgroundColor: colors[i]
                }));

                new Chart(severityCtx, {
                    type: 'bar',
                    data: {
                        labels: cweLabels, //x-axis: CWE types
                        datasets: datasets //stacks: severity per type
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Vulnerability Types by Severity' //dashboard headline
                            }
                        },
                        scales: {
                            x: {
                                stacked: true //stack severity segments next to each CWE
                            },
                            y: {
                                stacked: true //enable stacking vertically (standard for bar chart)
                            }
                        }
                    }
                });
            }
        }
    }
});


