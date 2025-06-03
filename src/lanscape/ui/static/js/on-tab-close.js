// This is the payload you want to send on unload.
// It can be as simple as JSON or just an empty POST.
function sendOnUnload() {
    const url = '/shutdown?type=browser-close';
    const data = JSON.stringify({ });
    // (1) Using navigator.sendBeacon
    if (navigator.sendBeacon) {
        const blob = new Blob([data], { type: 'application/json' });
        navigator.sendBeacon(url, blob);
    }
    // (2) Or—you can use fetch with keepalive (supported in modern browsers)
    else {
        fetch(url, {
        method: 'POST',
        body: data,
        headers: { 'Content-Type': 'application/json' },
        keepalive: true
        })
        .catch((err) => {
        // If it fails, there’s not much you can do here.
        console.warn('sendOnUnload fetch failed:', err);
        });
    }
}

// Attach to both beforeunload and unload to increase reliability.
// beforeunload fires slightly earlier, but some browsers block async work there.
window.addEventListener('beforeunload', sendOnUnload);
window.addEventListener('unload', sendOnUnload);