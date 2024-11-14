

$(document).ready(function() {
    // Load port lists into the dropdown
    getPortLists();
    
    $('#parallelism').on('input', function() {
        const val = $('#parallelism').val();
        let ans = val;

        if (parseFloat(val) > 1) {
            ans += ' <span>Warning: Increased parallelism may have inaccurate results<span>'
        }
        $('#parallelism-value').html(ans);
    });
    const scanId = getActiveScanId();
    if (scanId) {
        showScan(scanId);
    }
    

    // Handle form submission
    $('#scan-form').on('submit', function(event) {
        event.preventDefault();
        if ($('#scan-submit').text() == 'Scan') {
            submitNewScan()
        } else {
            terminateScan();
        }
        

    });

    // Handle filter input
    $('#filter').on('input', function() {
        const filter = $(this).val();
        const currentSrc = $('#ip-table-frame').attr('src');
        const newSrc = currentSrc.split('?')[0] + '?filter=' + filter;
        $('#ip-table-frame').attr('src', newSrc);
    });

});

function submitNewScan() {
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
}

function getActiveScanId() {
    const url = new URL(window.location.href);
    return url.searchParams.get('scan_id');
}

function showScan(scanId) {
    pollScanSummary(scanId);
    setScanState(false);

    $('#no-scan').addClass('div-hide');
    $('#scan-results').removeClass('div-hide');
    
    $('#export-link').attr('href','/export/' + scanId);
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

function setScanState(scanEnabled) {
    const button = $('#scan-submit');
    console.log('set scan state- scanning',scanEnabled)

    if (scanEnabled) {
        button.text("Scan");
        button.removeClass('btn-danger').addClass('btn-primary');
    } else {
        button.text("Stop");
        button.removeClass('btn-primary').addClass('btn-danger');
    }
}


function resizeIframe(iframe) {
    // Adjust the height of the iframe to match the content
    setTimeout( () => {
        iframe.style.height = iframe.contentWindow.document.body.scrollHeight + 'px';
    },100);
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
function terminateScan() {
    const button = $('#scan-submit');
    button.prop('disabled', true); 
    const scanId = getActiveScanId();
    $.get(`/api/scan/${scanId}/terminate`, function(ans) {
        setScanState(true);
        button.prop('disabled', false); 
    });
}
function pollScanSummary(id) {
    $.get(`/api/scan/${id}/summary`, function(summary) {
        let progress = $('#scan-progress-bar');
        if (summary.running || summary.stage == 'terminating') {
            progress.css('height','2px');
            progress.css('width',`${summary.percent_complete}vw`);
            // TODO: move overview here??
            setTimeout(() => {pollScanSummary(id)},500);
        } else {
            progress.css('width','100vw');
            progress.css('background-color','var(--success-accent)')
            setTimeout(() => {progress.css('height','0px');},500);
            setScanState(true);
            
            // wait to make the width smaller for animation to be clean
            setTimeout(() => {
                progress.css('width','0vw');
                progress.css('background-color','var(--primary-accent)')
            },1000);
        }
    });
}

// Bind the iframe's load event to initialize the observer
$('#ip-table-frame').on('load', function() {
    resizeIframe(this); // Initial resizing after iframe loads
    observeIframeContent(this); // Start observing for dynamic changes
});



$(window).on('resize', function() {
    resizeIframe($('#ip-table-frame')[0]);
});





