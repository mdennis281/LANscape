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
    $('#task_scan_port_services').on('change', updateVisibility);

    // Lookup type toggles
    $('.lookup-type-input').on('change', onLookupTypeChanged);
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

    // port scan config
    if (config.port_scan_config) {
        $('#port_scan_timeout').val(config.port_scan_config.timeout);
        $('#port_scan_retries').val(config.port_scan_config.retries);
        $('#port_scan_retry_delay').val(config.port_scan_config.retry_delay);
    } else {
        // defaults if missing
        $('#port_scan_timeout').val(1.0);
        $('#port_scan_retries').val(0);
        $('#port_scan_retry_delay').val(0.1);
    }

    // service config
    if (config.service_scan_config) {
        $('#service_lookup_type').val(config.service_scan_config.lookup_type || 'BASIC');
        $('#service_timeout').val(config.service_scan_config.timeout);
        $('#service_max_concurrent_probes').val(config.service_scan_config.max_concurrent_probes);
    } else {
        // defaults if missing
        $('#service_lookup_type').val('BASIC');
        $('#service_timeout').val(5.0);
        $('#service_max_concurrent_probes').val(10);
    }

    // lookup type (array of enum values as strings)
    setLookupTypeUI(config.lookup_type || []);

    // ping config
    $('#ping_attempts').val(config.ping_config.attempts);
    $('#ping_ping_count').val(config.ping_config.ping_count);
    $('#ping_retry_delay').val(config.ping_config.retry_delay);
    $('#ping_timeout').val(config.ping_config.timeout);

    // arp config
    $('#arp_attempts').val(config.arp_config.attempts);
    $('#arp_timeout').val(config.arp_config.timeout);

    // arp cache config
    if (config.arp_cache_config) {
        $('#arp_cache_attempts').val(config.arp_cache_config.attempts);
        $('#arp_cache_wait_before').val(config.arp_cache_config.wait_before);
    }

    // poke config
    if (config.poke_config) {
        $('#poke_attempts').val(config.poke_config.attempts);
        $('#poke_timeout').val(config.poke_config.timeout);
    }

    updatePortTotals();
    updatePingTotals();
    updateVisibility();
}

function getScanConfig() {
    return {
        port_list: $('#port_list').val(),
        t_cnt_port_scan: parseInt($('#t_cnt_port_scan').val()),
        t_cnt_port_test: parseInt($('#t_cnt_port_test').val()),
        t_cnt_isalive: parseInt($('#t_cnt_isalive').val()),
        task_scan_ports: $('#task_scan_ports').is(':checked'),
        task_scan_port_services: $('#task_scan_port_services').is(':checked'),
        lookup_type: getSelectedLookupTypes(),
        ping_config: {
            attempts: parseInt($('#ping_attempts').val()),
            ping_count: parseInt($('#ping_ping_count').val()),
            retry_delay: parseFloat($('#ping_retry_delay').val()),
            timeout: parseFloat($('#ping_timeout').val())
        },
        arp_config: {
            attempts: parseInt($('#arp_attempts').val()),
            timeout: parseFloat($('#arp_timeout').val())
        },
        arp_cache_config: {
            attempts: parseInt($('#arp_cache_attempts').val()),
            wait_before: parseFloat($('#arp_cache_wait_before').val())
        },
        poke_config: {
            attempts: parseInt($('#poke_attempts').val()),
            timeout: parseFloat($('#poke_timeout').val())
        },
        port_scan_config: {
            timeout: parseFloat($('#port_scan_timeout').val()),
            retries: parseInt($('#port_scan_retries').val()),
            retry_delay: parseFloat($('#port_scan_retry_delay').val())
        },
        service_scan_config: {
            timeout: parseFloat($('#service_timeout').val()),
            lookup_type: $('#service_lookup_type').val(),
            max_concurrent_probes: parseInt($('#service_max_concurrent_probes').val())
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

// Lookup type helpers
function setLookupTypeUI(values) {
    const set = new Set(values || []);
    $('.lookup-type-input').each(function() {
        const val = $(this).val();
        $(this).prop('checked', set.has(val));
    });
    updateVisibility();
}

function getSelectedLookupTypes() {
    const selected = [];
    $('.lookup-type-input:checked').each(function() {
        selected.push($(this).val());
    });
    return selected;
}

function onLookupTypeChanged() {
    updateVisibility();
}

function updateVisibility() {
    const types = new Set(getSelectedLookupTypes());

    // Show ping if ICMP is used directly or as part of ICMP_THEN_ARP
    const showPing = types.has('ICMP') || types.has('ICMP_THEN_ARP');
    toggleSection('#section-ping', showPing);

    // ARP active lookup (scapy) only when ARP_LOOKUP is selected
    const showArp = types.has('ARP_LOOKUP');
    toggleSection('#section-arp', showArp);

    // ARP cache is used when we do a staged lookup that relies on cache
    const showArpCache = types.has('ICMP_THEN_ARP') || types.has('POKE_THEN_ARP');
    toggleSection('#section-arp-cache', showArpCache);

    // Poke section only when POKE_THEN_ARP is selected
    const showPoke = types.has('POKE_THEN_ARP');
    toggleSection('#section-poke', showPoke);

    // Service scan section visible only if stage enabled
    const showService = $('#task_scan_port_services').is(':checked');
    toggleSection('#section-service-scan', showService);
}

function toggleSection(selector, show) {
    const $el = $(selector);
    if (show) $el.removeClass('div-hide');
    else $el.addClass('div-hide');
}

// expose functions globally
window.setScanConfig = setScanConfig;
window.getScanConfig = getScanConfig;
