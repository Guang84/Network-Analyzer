window.addEventListener('DOMContentLoaded', function() {
    // Get the iframe element
    var myconsole = document.getElementById('frame1');

    // List of file names (replace with your actual file names)
    var fileNames = ['file1.c', 'file2.c', 'file3.c']; // Add all your file names here

    // Function to fetch and display a C source code file
    function fetchAndDisplay(fileName) {
        fetch('source_code/' + fileName)
            .then(response => response.text())
            .then(code => {
                // Set the content of the iframe to the program code
                myconsole.contentDocument.open();
                myconsole.contentDocument.write('<h3>' + fileName + '</h3>');
                myconsole.contentDocument.write('<pre>' + code + '</pre>');
                myconsole.contentDocument.close();
            })
            .catch(error => console.error('Error fetching code:', error));
    }

    // Fetch and display each C source code file
    fileNames.forEach(fileName => {
        fetchAndDisplay(fileName);
    });
});
