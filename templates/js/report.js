document.addEventListener('DOMContentLoaded', function() {
    // Tab functionality for URL analysis cards
    const tabButtons = document.querySelectorAll('.tab-btn');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Get the parent tabs container
            const tabsContainer = this.parentElement;
            
            // Get the parent card to scope the selection
            const card = tabsContainer.parentElement;
            
            // Remove active class from all buttons in this card
            tabsContainer.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Add active class to clicked button
            this.classList.add('active');
            
            // Hide all tab contents in this card
            card.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Show the target tab content
            const targetId = this.getAttribute('data-target');
            card.querySelector(`#${targetId}`).classList.add('active');
        });
    });
}); 