$(document).ready(function () {
    // Update input box when selecting a dropdown item
    $('.dropdown-item').on('click', function (e) {
        e.preventDefault();
        let selectedSubnet = $(this).text();
        $('#subnet').val(selectedSubnet);  // Update input with selection
        subnetUpdated(selectedSubnet); // from subnet-info.js
    });
});