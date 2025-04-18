// Report page functionality
document.addEventListener('DOMContentLoaded', function() {
    // Handle tab switching
    const tabLinks = document.querySelectorAll('.nav-link[data-bs-toggle="tab"]');
    
    tabLinks.forEach(function(tabLink) {
        tabLink.addEventListener('click', function(e) {
            e.preventDefault();
            const target = this.getAttribute('data-bs-target');
            
            // Hide all tab content
            document.querySelectorAll('.tab-pane').forEach(function(pane) {
                pane.classList.remove('show', 'active');
            });
            
            // Deactivate all tabs
            tabLinks.forEach(function(link) {
                link.classList.remove('active');
            });
            
            // Show the selected tab content
            document.querySelector(target).classList.add('show', 'active');
            
            // Activate the clicked tab
            this.classList.add('active');
        });
    });
}); 