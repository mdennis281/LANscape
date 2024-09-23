// Validation for subnet input

$(document).ready(function() {
    $('#subnet').on('input', () => subnetUpdated($('#subnet').val()));
    subnetUpdated($('#subnet').val());
});

function subnetUpdated(input) {
    $.getJSON(`/api/tools/subnet/test?subnet=${input}`,(data) => {
        setSubnetValidity(data.valid);
        $('#subnet-info').html(data.msg);
    })
}

function setSubnetValidity(valid) { //boolean
    if (valid) $('#scan-form').removeClass('error');
    else $('#scan-form').addClass('error');
    $("#scan-submit").attr("disabled",!valid);
}