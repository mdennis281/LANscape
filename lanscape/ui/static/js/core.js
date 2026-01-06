$(document).ready(function() {
    rightSizeDocLayout(0,showFooter);
    initTooltips();
    adjustNoWrap();
})

$(window).on('resize', function() {
    rightSizeDocLayout();
    adjustNoWrap();
});


function rightSizeDocLayout(delay=20,callback=null) {
    setTimeout(() => {
        const content = $('#content');
        if (content) {
            const headerHeight = $('#header').outerHeight();
            const footerHeight = $('footer').outerHeight();
            const viewportHeight = $(window).height();

            const newHeight = viewportHeight - headerHeight - footerHeight;
            content.height(newHeight);
            
        }
        if (callback) callback();
    },delay);
}

function showFooter() {
    const footer = $('footer');
    footer.removeClass('div-hide');
    setTimeout(() => {footer.css('transform','translateY(0px)')},1);
}


function initTooltips() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl)
    })
}

/*
    An imperfect approach to adjusting 
    text field width within a table
*/
function adjustNoWrap() {
    $('.no-wrap').width(0);
    $('.no-wrap').each(function() {
        var parentWidth = $(this).parent().width();
        $(this).width(parseInt(parentWidth));
    });
}