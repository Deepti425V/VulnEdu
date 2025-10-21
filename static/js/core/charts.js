const ChartConfig = {
    // Centralized color palette matching application theme and security standards
    colors: {
        critical: '#f55855',    // Red for critical severity (universal danger color)
        high: '#f8a541',        // Orange for high severity (warning/urgency)
        medium: '#3b8ded',      // Blue for medium severity (informational)
        low: '#42d392',         // Green for low severity (safe/minimal risk)
        unknown: '#6b7280',     // Gray for unknown/undefined severity
        primary: '#63a4ff',     // Primary accent color for general chart elements
        secondary: '#94a3b8'    // Secondary color for supporting elements
    },

    // Default chart options for consistent appearance across all charts
    defaultOptions: {
        responsive: true,                    // Charts adapt to container size changes
        maintainAspectRatio: false,         // Allow flexible aspect ratios for different containers
        plugins: {
            legend: {
                labels: {
                    color: '#e2e8f0',       // Light color for legend text on dark background
                    font: { size: 12 }      // Consistent legend font size
                }
            }
        },
        scales: {
            x: {
                ticks: { color: '#94a3b8' },                    // Muted color for x-axis labels
                grid: { color: 'rgba(255,255,255,0.1)' }       // Subtle grid lines
            },
            y: {
                ticks: { color: '#94a3b8' },                    // Muted color for y-axis labels
                grid: { color: 'rgba(255,255,255,0.1)' }       // Subtle grid lines
            }
        }
    },

    // Severity colors as array for easy iteration in chart data
    severityColors: ['#f55855', '#f8a541', '#3b8ded', '#42d392', '#6b7280'],

    // Utility function to create linear gradients for enhanced chart styling
    createGradient: function(ctx, color1, color2) {
        const gradient = ctx.createLinearGradient(0, 0, 0, 400);  // Vertical gradient
        gradient.addColorStop(0, color1);      // Start color at top
        gradient.addColorStop(1, color2);      // End color at bottom
        return gradient;
    }
};

// Chart creation utilities providing factory methods for different chart types
const ChartUtils = {
    // Create doughnut-style pie chart for severity distribution visualization
    createPieChart: function(ctx, data, options = {}) {
        return new Chart(ctx, {
            type: 'doughnut',                   // Doughnut style provides space for central content
            data: data,
            options: {
                ...ChartConfig.defaultOptions,  // Apply base configuration
                cutout: options.cutout || '65%', // Default 65% cutout for doughnut hole
                ...options                      // Merge any additional custom options
            }
        });
    },

    // Create line chart for trend visualization and time series data
    createLineChart: function(ctx, data, options = {}) {
        return new Chart(ctx, {
            type: 'line',
            data: data,
            options: {
                ...ChartConfig.defaultOptions,  // Apply base configuration
                elements: {
                    line: { tension: 0.3 },     // Smooth curve without over-smoothing
                    point: { 
                        radius: 4,              // Visible points for data clarity
                        hoverRadius: 6          // Larger hover area for interaction
                    }
                },
                ...options                      // Merge any additional custom options
            }
        });
    },

    // Create bar chart for categorical data comparison
    createBarChart: function(ctx, data, options = {}) {
        return new Chart(ctx, {
            type: 'bar',
            data: data,
            options: {
                ...ChartConfig.defaultOptions,  // Apply base configuration
                ...options                      // Merge any additional custom options
            }
        });
    },

    // Create radar chart for multi-dimensional security analysis (e.g., CWE analysis)
    createRadarChart: function(ctx, data, options = {}) {
        return new Chart(ctx, {
            type: 'radar',
            data: data,
            options: {
                ...ChartConfig.defaultOptions,  // Apply base configuration
                scales: {
                    r: {                        // Radial scale configuration
                        angleLines: { 
                            color: 'rgba(255,255,255,0.1)' // Subtle angle lines
                        },
                        grid: { 
                            color: 'rgba(255,255,255,0.1)' // Subtle radial grid
                        },
                        pointLabels: {
                            color: '#a9adc1',   // Muted color for category labels
                            font: { 
                                size: 13,       // Readable font size for labels
                                weight: 'bold'  // Bold weight for emphasis
                            }
                        },
                        beginAtZero: true,      // Start scale from zero for accurate comparison
                        ticks: { display: false } // Hide tick marks to reduce clutter
                    }
                },
                ...options                      // Merge any additional custom options
            }
        });
    }
};