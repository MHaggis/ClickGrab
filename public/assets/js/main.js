
// ClickGrab interactive features
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('pre code').forEach(block => {
        const button = document.createElement('button');
        button.className = 'copy-btn';
        button.textContent = '📋 Copy';
        button.onclick = () => {
            navigator.clipboard.writeText(block.textContent);
            button.textContent = '✅ Copied!';
            setTimeout(() => button.textContent = '📋 Copy', 2000);
        };
        block.parentElement.style.position = 'relative';
        block.parentElement.appendChild(button);
    });
});
