// helps flask server know when the browser tab is closed


function sendOnUnload(event = null) {
    const url = '/shutdown?type=browser-close';
    const data = JSON.stringify({ event });
    console.log('sendOnUnload called:', data);
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
            // If it fails, there's not much you can do here.
            console.warn('sendOnUnload fetch failed:', err);
        });
    }
}

let hasBeenCalled = false;

// When pagehide is called w/ persist=false we want to send our payload.
// Wont work on all browsers, but should work on most modern ones.
window.addEventListener('pagehide', (event) => {
    if (!hasBeenCalled && !event.persisted) {
        // persisted = false means page is being discarded, not cached
        const clonedEvent = { 
            type: 'pagehide',
            persisted: event.persisted
        };
        sendOnUnload(clonedEvent);
        hasBeenCalled = true;
    }
});