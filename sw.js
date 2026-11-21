/* ESD Market — Service Worker (PWA)
   يخزّن هيكل التطبيق والأيقونات، ويترك ملفات الفيديو/الصوت للمتصفح (Range). */
const CACHE = "esd-market-v10";

const CORE = [
  "./",
  "./manifest.json",
  "./esd.jpg",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/icon-maskable-512.png",
  "./icons/apple-touch-icon.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await Promise.all(
      CORE.map((url) => cache.add(new Request(url, { cache: "reload" })).catch(() => {}))
    );
    self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  /* الصفحة: الشبكة أولاً مع رجوع للنسخة المخزّنة (يعمل بدون إنترنت) */
  if (req.mode === "navigate") {
    event.respondWith((async () => {
      try {
        const res = await fetch(req);
        if (res && res.ok) {
          const cache = await caches.open(CACHE);
          cache.put("./", res.clone()).catch(() => {});
        }
        return res;
      } catch (e) {
        return (await caches.match("./")) || (await caches.match(req)) || Response.error();
      }
    })());
    return;
  }

  /* كتالوج المنتجات وإعدادات Firebase: دائماً من الشبكة حتى تظهر التحديثات فوراً */
  if (/(products|firebase-applet-config)\.json$/i.test(url.pathname)) return;

  /* الوسائط الكبيرة تُدار من المتصفح مباشرة (طلبات Range) */
  if (/\.(mp4|webm|mp3)$/i.test(url.pathname)) return;

  event.respondWith((async () => {
    const cached = await caches.match(req);
    if (cached) return cached;
    try {
      const res = await fetch(req);
      if (res && res.ok && res.type === "basic") {
        const cache = await caches.open(CACHE);
        cache.put(req, res.clone()).catch(() => {});
      }
      return res;
    } catch (e) {
      return Response.error();
    }
  })());
});
