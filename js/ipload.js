function updateIPAddress() {
    document.getElementById('ipadd').textContent = window.location.href;
}
// Function to update browser status
function updateBrowserStatus() {
    var statusElement = document.getElementById('bstate');
    if (navigator.onLine) {
        statusElement.textContent = 'Online';
        statusElement.style.color = 'green';
    } else {
        statusElement.textContent = 'Offline';
        statusElement.style.color = 'red';
    }
}
// Call functions initially
updateIPAddress();
updateBrowserStatus();
// Add event listener to window for online/offline status changes
window.addEventListener('online', updateBrowserStatus);
window.addEventListener('offline', updateBrowserStatus);