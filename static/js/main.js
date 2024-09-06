$(document).ready(function() {
    // Load port lists into the dropdown
    getPortLists();
    $('#parallelism').on('input', function() {
        const value = $(this).val() + (value < 1) ? '' : ' Warning: Increasing parallelism may inaccuracy in the scan results.';

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
            port_list: $('#port-list').text(),
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
    // set url to the new url
    window.history.pushState({}, '', url);
}

function getPortLists() {
    $.get('/api/port/list', function(data) {
        const customSelect = $('#port-list');
        const customSelectDropdown = $('#port-list-dropdown');
        customSelectDropdown.empty();
    
        // Populate the dropdown with the options
        data.forEach(function(portList) {
            customSelectDropdown.append('<div>' + portList + '</div>');
        });
    
        // Set the default value
        customSelect.text('medium');
    
        // Handle dropdown click
        customSelect.on('click', function() {
            customSelectDropdown.toggleClass('open');
        });
    
        // Handle option selection
        customSelectDropdown.on('click', 'div', function() {
            const selectedOption = $(this).text();
            customSelect.text(selectedOption);
            customSelectDropdown.removeClass('open');
        });
    });
}

$(document).on('click', function(event) {
    if (!$(event.target).closest('.port-list-wrapper').length) {
        $('#port-list-dropdown').removeClass('open');
    }
});


function resizeIframe(iframe) {
    // Adjust the height of the iframe to match the content
    iframe.style.height = iframe.contentWindow.document.body.scrollHeight + 'px';
}

function observeIframeContent(iframe) {
    const iframeDocument = iframe.contentDocument || iframe.contentWindow.document;

    // Use MutationObserver to observe changes within the iframe
    const observer = new MutationObserver(() => {
        resizeIframe(iframe);
    });

    // Configure the observer to watch for changes in the subtree of the body
    observer.observe(iframeDocument.body, {
        childList: true,
        subtree: true,
        attributes: true,  // In case styles/attributes change height
    });
}

// Bind the iframe's load event to initialize the observer
$('#ip-table-frame').on('load', function() {
    resizeIframe(this); // Initial resizing after iframe loads
    observeIframeContent(this); // Start observing for dynamic changes
});
