(function () {
  const ENDPOINT = "http://localhost:8000/api/v1/track";

  // Persistent anonymous visitor ID
  let visitorId = localStorage.getItem("_monetize_uid");
  if (!visitorId) {
    visitorId = "usr_" + Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
    localStorage.setItem("_monetize_uid", visitorId);
  }

  function sendTelemetry(eventType, metadata = {}) {
    const payload = JSON.stringify({
      visitor_id: visitorId,
      url: window.location.href,
      referrer: document.referrer || null,
      event_type: eventType,
      timestamp: new Date().toISOString(),
      metadata: metadata,
    });

    if (navigator.sendBeacon) {
      const blob = new Blob([payload], { type: "application/json" });
      navigator.sendBeacon(ENDPOINT, blob);
    } else {
      fetch(ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
        keepalive: true,
      }).catch(() => {});
    }
  }

  // 1. Pageview capture
  window.addEventListener("DOMContentLoaded", () => {
    sendTelemetry("pageview", {
      title: document.title,
      screen: `${window.screen.width}x${window.screen.height}`,
    });
  });

  // 2. Click capture on buttons, links, and annotated elements
  document.addEventListener("click", (e) => {
    const target = e.target.closest("button, a, [data-monetize]");
    if (!target) return;

    sendTelemetry("click", {
      tag: target.tagName.toLowerCase(),
      id: target.id || null,
      monetize_key: target.getAttribute("data-monetize") || null,
      text: (target.innerText || "").substring(0, 40).trim(),
    });
  });

  // Expose visitor ID globally for the UI
  window.__visitorId = visitorId;
})();
