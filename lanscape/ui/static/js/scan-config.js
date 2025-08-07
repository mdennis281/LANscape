let defaultScanConfigs = {};
let activeConfigName = 'balanced';

$(document).ready(function() {
    // load port lists
    getPortLists(function() {
        // THEN get scan config defaults
        getScanDefaults(function() {
            // THEN set the default scan config
            setScanConfig('balanced');
        })
    });
    
    $('#t_cnt_port_scan, #t_cnt_port_test').on('input', updatePortTotals);
    $('#ping_attempts, #ping_ping_count').on('input', updatePingTotals);
});

function getScanDefaults(callback=null) {
    $.getJSON('/api/tools/config/defaults', (data) => {
        defaultScanConfigs = data;
        if (callback) callback();
    });
}

function setScanConfig(configName) {
    const config = defaultScanConfigs[configName];
    if (!config) return;
    activeConfigName = configName;

    // highlight selected preset
    $('.config-option').removeClass('active');
    $(`#config-${configName}`).addClass('active');

    // basic settings
    $('#port_list').val(config.port_list);
    $('#t_multiplier').val(config.t_multiplier);
    $('#t_cnt_port_scan').val(config.t_cnt_port_scan);
    $('#t_cnt_port_test').val(config.t_cnt_port_test);
    $('#t_cnt_isalive').val(config.t_cnt_isalive);
    $('#task_scan_ports').prop('checked', config.task_scan_ports);
    $('#task_scan_port_services').prop('checked', config.task_scan_port_services);
    $('#lookup_type').val(config.lookup_type);

    // ping config
    $('#ping_attempts').val(config.ping_config.attempts);
    $('#ping_ping_count').val(config.ping_config.ping_count);
    $('#ping_retry_delay').val(config.ping_config.retry_delay);
    $('#ping_timeout').val(config.ping_config.timeout);

    // arp config
    $('#arp_attempts').val(config.arp_config.attempts);
    $('#arp_timeout').val(config.arp_config.timeout);

    updatePortTotals();
    updatePingTotals();
}

function getScanConfig() {
    return {
        port_list: $('#port_list').val(),
        t_cnt_port_scan: parseInt($('#t_cnt_port_scan').val()),
        t_cnt_port_test: parseInt($('#t_cnt_port_test').val()),
        t_cnt_isalive: parseInt($('#t_cnt_isalive').val()),
        task_scan_ports: $('#task_scan_ports').is(':checked'),
        task_scan_port_services: $('#task_scan_port_services').is(':checked'),
        lookup_type: $('#lookup_type').val(),
        ping_config: {
            attempts: parseInt($('#ping_attempts').val()),
            ping_count: parseInt($('#ping_ping_count').val()),
            retry_delay: parseFloat($('#ping_retry_delay').val()),
            timeout: parseFloat($('#ping_timeout').val())
        },
        arp_config: {
            attempts: parseInt($('#arp_attempts').val()),
            timeout: parseFloat($('#arp_timeout').val())
        }
    };
}

function getPortLists(callback=null) {
    $.get('/api/port/list', function(data) {
        const customSelectDropdown = $('#port_list');
        customSelectDropdown.empty();
    
        // Populate the dropdown with the options
        data.forEach(function(portList) {
            customSelectDropdown.append('<option>' + portList + '</option>');
        });
        if (callback) callback();
    });
}

function updatePortTotals() {
    const scan = parseInt($('#t_cnt_port_scan').val()) || 0;
    const test = parseInt($('#t_cnt_port_test').val()) || 0;
    $('#total-port-tests').val(scan * test);
}

function updatePingTotals() {
    const attempts = parseInt($('#ping_attempts').val()) || 0;
    const count = parseInt($('#ping_ping_count').val()) || 0;
    $('#total-ping-attempts').val(attempts * count);
}

// expose functions globally
window.setScanConfig = setScanConfig;
window.getScanConfig = getScanConfig;
