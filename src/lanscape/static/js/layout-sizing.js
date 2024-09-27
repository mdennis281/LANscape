$(document).ready(function() {
    rightSizeDocLayout(0,showFooter);
})

$(window).on('resize', function() {
    rightSizeDocLayout();
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

