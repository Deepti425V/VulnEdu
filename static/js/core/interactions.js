// Event handlers and interactions
const Interactions = {
    // Initialize all interactions
    init: function() {
        this.initSeverityCards();
        this.initChartClicks();
        this.initSearchFilters();
        this.initTooltips();
    },

    // Severity card click handlers
    initSeverityCards: function() {
        document.querySelectorAll(".severity-card").forEach(function(card) {
            card.addEventListener("click", function() {
                var sev = card.getAttribute("data-severity");
                if (sev) {
                    window.location.href = "/vulnerabilities?severity=" + encodeURIComponent(sev);
                }
            });

            card.addEventListener("mouseenter", function() {
                card.style.boxShadow = "0 0 0 3px #63a4ff44";
            });

            card.addEventListener("mouseleave", function() {
                card.style.boxShadow = "";
            });
        });
    },

    // Chart click handlers
    initChartClicks: function() {
        // These will be implemented in specific page JS files
        // This is just the base structure
    },

    // Search and filter interactions
    initSearchFilters: function() {
        // Auto-submit forms on filter change
        const filterSelects = document.querySelectorAll('select[name="severity"], select[name="year"], select[name="month"]');
        filterSelects.forEach(select => {
            select.addEventListener('change', function() {
                // Auto-submit the form when filter changes
                const form = this.closest('form');
                if (form) {
                    form.submit();
                }
            });
        });

        // Search input debouncing
        const searchInputs = document.querySelectorAll('input[name="q"]');
        searchInputs.forEach(input => {
            let debounceTimer;
            input.addEventListener('input', function() {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    // Could implement live search here
                }, 500);
            });
        });
    },

    // Tooltip initialization
    initTooltips: function() {
        document.querySelectorAll('[data-tooltip]').forEach(element => {
            element.addEventListener('mouseenter', this.showTooltip);
            element.addEventListener('mouseleave', this.hideTooltip);
        });
    },

    showTooltip: function(event) {
        const tooltip = document.createElement('div');
        tooltip.className = 'custom-tooltip';
        tooltip.textContent = event.target.getAttribute('data-tooltip');
        tooltip.style.cssText = `
            position: absolute;
            background: #1a2236;
            color: #e2e8f0;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.9em;
            z-index: 1000;
            pointer-events: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        `;
        
        document.body.appendChild(tooltip);
        
        const rect = event.target.getBoundingClientRect();
        tooltip.style.left = rect.left + 'px';
        tooltip.style.top = (rect.bottom + 5) + 'px';
        
        event.target._tooltip = tooltip;
    },

    hideTooltip: function(event) {
        if (event.target._tooltip) {
            document.body.removeChild(event.target._tooltip);
            delete event.target._tooltip;
        }
    }
};

// Initialize interactions when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    Interactions.init();
});