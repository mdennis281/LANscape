let defaultScanConfigs = {};

$(document).ready(function() {
    getScanDefaults(function() {
        setScanConfig('balanced');
    });
});

function getScanDefaults(callback=null) {
    $.getJSON(`/api/tools/config/defaults`,(data) => {
        defaultScanConfigs = data;
        if (callback) callback();
    });
}

function setScanConfig(configName) {
    const config = defaultScanConfigs[configName];
    console.log(`Setting scan config to ${configName}`, config);
    if (config) {
        $('#scan-config').val(JSON.stringify(config, null, 2));
        $('#port-list').val(config.port_list),
        $('#parallelism').val(config.port_list)
        // more to come
    }
}