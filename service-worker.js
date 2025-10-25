// (service-worker.js)

self.addEventListener('push', event => {
  const data = event.data.json();
  
  const options = {
    body: data.body,
    icon: 'icon.png', // (आपको एक icon.png फ़ाइल भी डालनी होगी)
    badge: 'badge.png' // (आपको एक badge.png फ़ाइल भी डालनी होगी)
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});