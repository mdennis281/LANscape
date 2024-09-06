$(document).ready(function() {
    // Load port lists into the dropdown
    $.get('/api/port/list', function(data) {
        const portListSelect = $('#port_list');
        data.forEach(function(portList) {
            portListSelect.append(new Option(portList, portList));
        });
        portListSelect.val('medium');
    });
    $('#parallelism').on('input', function() {
        $('#parallelism-value').text($(this).val());
    });
    const url = new URL(window.location.href);
    if (url.searchParams.get('scan_id')) {
        showScan(url.searchParams.get('scan_id'));
    }
    

    // Handle form submission
    $('#scan-form').on('submit', function(event) {
        event.preventDefault();
        const formData = {
            subnet: $('#subnet').val(),
            port_list: $('#port_list').val(),
            parallelism: $('#parallelism').val()
        };
        $.ajax('/api/scan', {
            data : JSON.stringify(formData),
            contentType : 'application/json',
            type : 'POST',
            success: function(response) {
                if (response.status === 'running') {
                    showScan(response.scan_id);
                }
            }
        });

    });

    // Handle filter input
    $('#filter').on('input', function() {
        const filter = $(this).val();
        const currentSrc = $('#ip-table-frame').attr('src');
        const newSrc = currentSrc.split('?')[0] + '?filter=' + filter;
        $('#ip-table-frame').attr('src', newSrc);
    });
});

function showScan(scanId) {
    $('#scan-results').show();
    $('#overview-frame').attr('src', '/scan/' + scanId + '/overview');
    $('#ip-table-frame').attr('src', '/scan/' + scanId + '/table');
    // set url query string 'scan_id' to the scan_id
    const url = new URL(window.location.href);
    url.searchParams.set('scan_id', scanId);
}

// Functions to handle button actions (example only)
function openHttp(ip) {
    window.open('http://' + ip);
}

function openSsh(ip) {
    window.open('ssh://' + ip);
}

function resizeIframe(iframe) {
    iframe.style.height = iframe.contentWindow.document.body.scrollHeight + 'px';
}

// Bind iframe height adjustment
document.getElementById('overview-frame').onload = function() {
    resizeIframe(this);
};

document.getElementById('ip-table-frame').onload = function() {
    resizeIframe(this);
};