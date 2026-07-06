import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const setupHtml = fs.readFileSync(new URL('../html/setup.html', import.meta.url), 'utf8');
const updateStart = setupHtml.indexOf('function setUpdateButtons');
const updateEnd = setupHtml.indexOf('/* ---- Schedules', updateStart);
assert.ok(updateStart > 0 && updateEnd > updateStart, 'Setup update script block must exist');
const updateSource = setupHtml.slice(updateStart, updateEnd);

function response(data, { ok = true, status = 200 } = {}) {
    return { ok, status, json: async () => data };
}

function harness() {
    let nextTimer = 1;
    const timers = new Map();
    const replacements = [];
    const status = { text: '', cls: '' };
    const done = {};
    let fetchImpl = async () => response({ success: true });
    let dirty = false;

    const output = {
        _text: '',
        scrollTop: 0,
        clientHeight: 100,
        get scrollHeight() { return 100 + this._text.length; },
        get textContent() { return this._text; },
        set textContent(value) { this._text = String(value); },
    };
    const elements = {
        'update-output': output,
        'update-btn': { disabled: false },
        'offline-upload-btn': { disabled: false },
    };
    const context = vm.createContext({
        AbortController,
        Date,
        DOMException,
        URL,
        console,
        document: { getElementById: (id) => elements[id] || null },
        fetch: (...args) => fetchImpl(...args),
        location: {
            href: 'http://lldpq.test/setup.html?step=update',
            replace: (value) => replacements.push(value),
        },
        setTimeout: (callback, delay) => {
            const id = nextTimer++;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeout: (id) => timers.delete(id),
        setStatus: (_id, text, cls) => { status.text = text; status.cls = cls; },
        markDone: (key, value) => { done[key] = value; },
        hasUnsavedSetupChanges: () => dirty,
    });

    vm.runInContext(`
        const STEPS = [{ key:'update' }];
        let current = 0;
        let updateActive = false;
        let updatePollTimer = null;
        let updateJobId = null;
        let updatePollEpoch = 0;
        let updatePollController = null;
        let updateReloadScheduled = false;
        const UPDATE_LOG_TIMEOUT_MS = 10000;
        ${updateSource}
        globalThis.__updateTest = {
            pollUpdateLog,
            showUpdateLog,
            state: () => ({ updateActive, updateJobId, updatePollEpoch, updatePollController, updateReloadScheduled }),
            setState: (value) => {
                if ('active' in value) updateActive = value.active;
                if ('jobId' in value) updateJobId = value.jobId;
                if ('epoch' in value) updatePollEpoch = value.epoch;
            }
        };
    `, context);

    async function runTimer(delay) {
        const found = [...timers.entries()].find(([, timer]) => timer.delay === delay);
        assert.ok(found, `expected a ${delay}ms timer`);
        timers.delete(found[0]);
        return await found[1].callback();
    }

    return {
        api: context.__updateTest,
        done,
        elements,
        output,
        replacements,
        status,
        timers,
        runTimer,
        setDirty: (value) => { dirty = value; },
        setFetch: (value) => { fetchImpl = value; },
    };
}

test('transient 502 without a job id retries instead of claiming another job', async () => {
    const h = harness();
    const job = 'a'.repeat(32);
    h.api.setState({ active: true, jobId: job, epoch: 7 });
    h.setFetch(async () => response(null, { ok: false, status: 502 }));

    await h.api.pollUpdateLog(7);

    assert.equal(h.api.state().updateActive, true);
    assert.match(h.status.text, /Reconnecting/);
    assert.doesNotMatch(h.status.text, /replaced by another job/);
    assert.equal([...h.timers.values()].some((timer) => timer.delay === 2500), true);

    h.output.scrollTop = 0; // operator looked at earlier output while it was running
    h.setFetch(async () => response({
        success: true,
        job_id: job,
        running: false,
        done: true,
        ok: true,
        exit_code: 0,
        log: 'start\ninstall complete\nfinal marker',
    }));
    await h.runTimer(2500);

    assert.equal(h.api.state().updateActive, false);
    assert.equal(h.output.textContent.endsWith('final marker'), true);
    assert.equal(h.output.scrollTop, h.output.scrollHeight);
    assert.equal(h.elements['update-btn'].disabled, false);
    assert.equal(h.done.update, true);
    assert.match(h.status.text, /loading the updated UI/);

    await h.runTimer(700);
    assert.equal(h.replacements.length, 1);
    assert.match(h.replacements[0], /step=update/);
    assert.match(h.replacements[0], new RegExp(`_updated=${job}`));
});

test('a log request hung across nginx restart is aborted and polling resumes', async () => {
    const h = harness();
    const job = 'b'.repeat(32);
    h.api.setState({ active: true, jobId: job, epoch: 3 });
    h.setFetch((_url, options) => new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
    }));

    const pendingPoll = h.api.pollUpdateLog(3);
    await h.runTimer(10000);
    await pendingPoll;

    assert.equal(h.api.state().updateActive, true);
    assert.match(h.status.text, /Reconnecting/);
    assert.equal([...h.timers.values()].some((timer) => timer.delay === 2500), true);

    h.setFetch(async () => response({
        success: true, job_id: job, running: true, done: false,
        ok: false, exit_code: null, log: 'services restarted; continuing',
    }));
    await h.runTimer(2500);
    assert.equal(h.api.state().updateActive, true);
    assert.equal(h.output.textContent, 'services restarted; continuing');
    assert.equal([...h.timers.values()].some((timer) => timer.delay === 2500), true);
});

test('only an explicit different job id stops the current poller', async () => {
    const h = harness();
    const original = 'c'.repeat(32);
    const replacement = 'd'.repeat(32);
    h.api.setState({ active: true, jobId: original, epoch: 2 });
    h.setFetch(async () => response({
        success: true, job_id: replacement, running: true, done: false, log: 'other job',
    }));

    await h.api.pollUpdateLog(2);

    assert.equal(h.api.state().updateActive, false);
    assert.match(h.status.text, /replaced by another job/);
    assert.equal([...h.timers.values()].some((timer) => timer.delay === 2500), false);
    assert.equal(h.replacements.length, 0);
});

