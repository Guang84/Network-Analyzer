window.onload = function() {
    const terminal = document.getElementById('terminal');

    // Create a WebSocket connection to the server
    const socket = new WebSocket('ws://localhost:3000');

    // Update the terminal content when a message is received from the server
    socket.onmessage = function(event) {
        terminal.innerHTML += event.data + '<br>';
        terminal.scrollTop = terminal.scrollHeight;
    };
};
