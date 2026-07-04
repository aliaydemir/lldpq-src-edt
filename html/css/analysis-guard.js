/*
 * analysis-guard.js — hide the admin-only "Run Analysis" button for operators.
 *
 * The button triggers /trigger-monitor (a full fabric-wide collection) which is
 * admin-only; an operator would only get "Failed to trigger analysis", so the
 * button should not be shown to them.
 *
 * Flicker-free: this script sits at end-of-body, so it runs before first paint.
 * It first hides synchronously using the role cached by auth.js (written when the
 * app shell ran its auth check), so operators never see the button flash. It then
 * confirms/refreshes the role from /auth-api. Read-only and side-effect free:
 * no redirect, and on any failure / unknown role the button is left as-is, so
 * non-auth deployments keep working.
 */
// Load the shared dark-themed dialogs on every analysis page so any native alert()
// (e.g. "Failed to trigger analysis", CSV export errors) is rendered in our dark UI.
(function () {
    if (window.__lldpqDialogsLoaded || window.__lldpqDialogsRequested) return;
    window.__lldpqDialogsRequested = true;
    try {
        var s = document.createElement('script');
        s.src = '/css/ui-dialogs.js';
        (document.head || document.documentElement).appendChild(s);
    } catch (e) {}
})();

(function () {
    function setHidden(hidden) {
        var b = document.getElementById('run-analysis');
        if (b) b.style.display = hidden ? 'none' : '';
    }

    // 1) Synchronous fast-path from the cached role -> no network, no flicker.
    var cached = null;
    try { cached = localStorage.getItem('lldpq_role'); } catch (e) {}
    if (cached && cached !== 'admin') setHidden(true);

    // 2) Confirm / refresh from the server (covers first visit or a stale cache).
    fetch('/auth-api?action=check')
        .then(function (r) { return r.json(); })
        .then(function (d) {
            if (d && d.role) {
                try { localStorage.setItem('lldpq_role', d.role); } catch (e) {}
                if (d.role !== 'admin') setHidden(true);
            }
        })
        .catch(function () { /* leave the button as-is */ });
})();

/*
 * Shared monitoring-run state helpers.
 *
 * Analysis pages are last-known-good snapshots.  A trigger response only means
 * that a collection was queued; it does not mean the new report is ready.  Keep
 * the existing page layout and let page scripts wait for a new current manifest
 * instead of blindly reloading after a fixed delay.
 */
(function () {
    function noCacheUrl(path) {
        return path + (path.indexOf('?') === -1 ? '?' : '&') + '_=' + Date.now();
    }

    function parseStateMarker(text) {
        var result = {};
        String(text || '').split(/\r?\n/).forEach(function (line) {
            var index = line.indexOf('=');
            if (index > 0) result[line.slice(0, index)] = line.slice(index + 1);
        });
        return result;
    }

    async function readPipelineState() {
        var marker = null;
        var manifest = null;
        try {
            var markerResponse = await fetch(noCacheUrl('/monitor-results/.lldpq-stale'), {
                cache: 'no-store'
            });
            if (markerResponse.ok) marker = parseStateMarker(await markerResponse.text());
        } catch (error) {}
        try {
            var manifestResponse = await fetch(noCacheUrl('/monitor-results/.lldpq-current.json'), {
                cache: 'no-store'
            });
            if (manifestResponse.ok) manifest = await manifestResponse.json();
        } catch (error) {}
        return { marker: marker, manifest: manifest };
    }

    function manifestIdentity(manifest) {
        if (!manifest || typeof manifest !== 'object') return '';
        return String(manifest.pipeline_id || manifest.completed_at || '');
    }

    function delay(milliseconds) {
        return new Promise(function (resolve) { setTimeout(resolve, milliseconds); });
    }

    window.lldpqReadPipelineState = readPipelineState;
    window.lldpqCapturePipelineState = readPipelineState;
    window.waitForLldpqAnalysisCompletion = async function (baseline, options) {
        options = options || {};
        var timeoutMs = Number(options.timeoutMs) || 15 * 60 * 1000;
        var pollMs = Math.max(Number(options.pollMs) || 2000, 500);
        var startedAt = Date.now();
        var baselineIdentity = manifestIdentity(baseline && baseline.manifest);
        var sawCollection = false;

        while (Date.now() - startedAt < timeoutMs) {
            var state = await readPipelineState();
            var markerStatus = state.marker && state.marker.status;
            if (markerStatus === 'collecting') sawCollection = true;
            if (markerStatus === 'stale') {
                throw new Error((state.marker && state.marker.reason) || 'Monitoring run failed');
            }

            var currentIdentity = manifestIdentity(state.manifest);
            var manifestCurrent = state.manifest &&
                state.manifest.status === 'current' &&
                state.manifest.pipeline_complete === true;
            var isNewManifest = currentIdentity && currentIdentity !== baselineIdentity;
            if (!markerStatus && manifestCurrent && (isNewManifest || sawCollection || !baselineIdentity)) {
                return state.manifest;
            }
            await delay(pollMs);
        }
        throw new Error('Monitoring run did not complete before the timeout');
    };

    // Preserve the current visual structure: reuse the existing timestamp line
    // to state that its snapshot is LKG while a run is collecting or stale.
    readPipelineState().then(function (state) {
        var status = state.marker && state.marker.status;
        if (status !== 'collecting' && status !== 'stale') return;
        var timestamp = document.querySelector('.last-updated');
        if (!timestamp) return;
        var suffix = status === 'collecting'
            ? ' — collection in progress; showing previous report'
            : ' — latest collection failed; showing previous report';
        if (timestamp.textContent.indexOf(suffix) === -1) timestamp.textContent += suffix;
        document.body.setAttribute('data-pipeline-status', status);
    }).catch(function () {});
})();
