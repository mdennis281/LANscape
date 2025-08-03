// Reload the page gracefully every second
// Used in 'live' iframes

function quietReload() {
    function run() {
        $.get(document.location.href, function(data) {
            // create a new document from the fetched data
            var newDoc = new DOMParser().parseFromString(data, 'text/html');
            // replace current body with the new body content
            $('body').html($(newDoc.body).html());
        });
    }
    setTimeout(function() {
        // get current page via ajax, and replace the current page with the new one
        try {
            run();
        } catch (e) {
            console.error(e);
            quietReload();
        }
    }, 1000);
}
quietReload();