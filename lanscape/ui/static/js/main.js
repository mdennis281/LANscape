

$(document).ready(function() {
    // Load port lists into the dropdown
    const scanId = getActiveScanId();
    if (scanId) {
        showScan(scanId);
    }

    // this prevents the browser from
    // triggering the shutdown beacon
    // when user clicks the logo
    setUrlParam('loaded', 'true')
    

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

    $('#settings-btn').on('click', function() {
        $('#advanced-modal').modal('show');
    });

});

function submitNewScan() {
    const config = getScanConfig();
    config.subnet = $('#subnet').val();
    $.ajax('/api/scan', {
        data: JSON.stringify(config),
        contentType: 'application/json',
        type: 'POST',
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
    //$('#overview-frame').attr('src', '/scan/' + scanId + '/overview');
    $('#ip-table-frame').attr('src', '/scan/' + scanId + '/table');
    
    setUrlParam('scan_id', scanId);
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
        updateOverviewUI(summary);
    }).fail(function(req) {
        if (req === 404) {
            console.log('Scan not found, redirecting to home');
            window.location.href = '/';
        }
    });
}

function updateOverviewUI(summary) {
    // helper to turn a number of seconds into "MM:SS"
    function formatMMSS(totalSeconds) {
      const secs = Math.floor(totalSeconds);
      const m = Math.floor(secs / 60);
      const s = secs % 60;
      // pad minutes and seconds to 2 digits
      const mm = String(m).padStart(2, '0');
      const ss = String(s).padStart(2, '0');
      return `${mm}:${ss}`;
    }
  
    const alive       = summary.devices.alive;
    const scanned     = summary.devices.scanned;
    const total       = summary.devices.total;
  
    // ensure we have a number of elapsed seconds
    const runtimeSec  = parseFloat(summary.runtime) || 0;
    const pctComplete = Number(summary.percent_complete) || 0;
  
    // compute remaining seconds correctly
    const remainingSec = pctComplete > 0
      ? (runtimeSec * (100 - pctComplete)) / pctComplete
      : 0;
  
    // update everything…
    $('#scan-devices-alive').text(alive);
    $('#scan-devices-scanned').text(scanned);
    $('#scan-devices-total').text(total);
  
    // …but format runtime and remaining as MM:SS
    $('#scan-run-time').text(formatMMSS(runtimeSec));
    if (pctComplete < 10) {
        $('#scan-remain-time').text('??:??');
    } else {
        $('#scan-remain-time').text(formatMMSS(remainingSec));
    }
    
  
    $('#scan-stage').text(summary.stage);
}

// Bind the iframe's load event to initialize the observer
$('#ip-table-frame').on('load', function() {
    resizeIframe(this); // Initial resizing after iframe loads
    observeIframeContent(this); // Start observing for dynamic changes
});

function setUrlParam(param, value) {
    const url = new URL(window.location.href);
    if (value === null || value === undefined) {
        url.searchParams.delete(param);
    } else {
        url.searchParams.set(param, value);
    }
    window.history.pushState({}, '', url);
}



$(window).on('resize', function() {
    resizeIframe($('#ip-table-frame')[0]);
});





