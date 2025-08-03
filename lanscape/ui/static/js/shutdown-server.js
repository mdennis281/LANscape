$(document).ready(function() {
    setTimeout(() => shutdownApp(), 2000);
});



function shutdownApp() {
    // will term server before response
    $.get('/shutdown').always(() => serverDown());
}

function serverDown() {
    $('#shutdown-message').html('Server down.');
    $('#shutdown-sub').html('You can close this browser window.');
    $('#shutdown-sub-sub').html('(since your browser wont let me)');
    setTimeout(() => window.close(),2500);
}