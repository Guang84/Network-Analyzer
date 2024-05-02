// ./js/onload.js
$(document).ready(function() {
    // Fetch server status and IP address
    $.get('/server/status', function(data) {
        // Update server status
        $('#bstate').text(data.status);

        // Update IP address
        $('#ipadd').text(data.ipAddress);
    });
});
