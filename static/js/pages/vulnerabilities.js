// Wait for DOM to be fully constructed before setting up interactive features
document.addEventListener('DOMContentLoaded', function() {
    // Toggle Critical/High section
    // Exposed globally so HTML onclick attributes can access it easily
    window.toggleCriticalHighSection = function() {
        const content = document.getElementById('criticalHighContent');  // Get collapsible content area
        const icon = document.getElementById('collapseIcon');            // Get expand/collapse indicator
        
        // Check current visibility state and toggle
        if (content.style.display === 'none') {
            content.style.display = 'block';  // Show content
            icon.textContent = '▼';            // Down arrow indicates expanded
        } else {
            content.style.display = 'none';   // Hide content
            icon.textContent = '▶';            // Right arrow indicates collapsed
        }
    };

    // Row hover effects for vulnerability table
    // Provides visual feedback when users hover over table rows
    const tableRows = document.querySelectorAll('.vuln-table tbody tr');
    tableRows.forEach(row => {
        // Mouse enters row - highlight with darker background
        row.addEventListener('mouseenter', function() {
            this.style.backgroundColor = '#212d46';  // Darker blue for hover state
        });
        
        // Mouse leaves row - restore original background
        row.addEventListener('mouseleave', function() {
            this.style.backgroundColor = '#1a2236';  // Original dark background
        });
    });

    // Auto-submit forms on filter change
    // Provides instant filtering without requiring submit button clicks
    const filterSelects = document.querySelectorAll('select[name="severity"], select[name="year"], select[name="month"]');
    filterSelects.forEach(select => {
        select.addEventListener('change', function() {
            // Find the parent form element using DOM traversal
            const form = this.closest('form');
            if (form) {
                form.submit();  // Automatically submit form when filter changes
            }
        });
    });

    // Search input handling
    // Allows users to press Enter to submit search instead of clicking submit button
    const searchInput = document.querySelector('input[name="q"]');
    if (searchInput) {  // Only attach if search input exists on page
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {  // Check if Enter key was pressed
                // Find parent form and submit search
                const form = this.closest('form');
                if (form) {
                    form.submit();  // Submit search form
                }
            }
        });
    }
});