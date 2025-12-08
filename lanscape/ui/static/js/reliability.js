const initialReliabilityState = window.initialReliabilityState || {};
let reliabilityJobs = initialReliabilityState.jobs || [];
let reliabilityMetrics = initialReliabilityState.metrics || null;
let reliabilityPollTimer = null;
let reliabilityMetricsTimer = null;
const METRICS_POLL_INTERVAL = 5000;

$(document).ready(function() {
    bindReliabilityEvents();
    renderReliabilityJobs(reliabilityJobs);
    renderReliabilityMetrics(reliabilityMetrics);
    scheduleReliabilityPoll();
    scheduleMetricsPoll();
});

function bindReliabilityEvents() {
    $('#reliability-settings-btn').on('click', function() {
        $('#advanced-modal').modal('show');
    });

    $('#reliability-form').on('submit', function(event) {
        event.preventDefault();
        queueReliabilityRuns();
    });

    $('[aria-labelledby="reliability-subnet-dropdown"] .dropdown-item').on('click', function(event) {
        event.preventDefault();
        const value = $(this).data('value') || $(this).text();
        $('#reliability-subnet').val(value);
    });

    $('#reliability-queue').on('click', '.btn-cancel-job', function() {
        const jobId = $(this).data('job');
        cancelReliabilityJob(jobId);
    });
}

function queueReliabilityRuns() {
    const button = $('#queue-submit');
    button.prop('disabled', true).text('Queuing...');

    const config = getScanConfig();
    config.subnet = $('#reliability-subnet').val();

    const payload = {
        config: config,
        runs: parseInt($('#run-count').val(), 10) || 1,
        label: $('#run-label').val() || null,
    };

    $.ajax('/api/reliability/jobs', {
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(payload),
        success: function(response) {
            $('#run-label').val('');
            reliabilityJobs = (response.jobs || []).concat(reliabilityJobs);
            renderReliabilityJobs(reliabilityJobs);
            fetchReliabilityJobs();
        },
        error: function(xhr) {
            const message = xhr.responseJSON?.error || 'Unable to queue run(s)';
            alert(message);
        },
        complete: function() {
            button.prop('disabled', false).text('Queue');
        }
    });
}

function cancelReliabilityJob(jobId) {
    if (!jobId) return;
    $.post(`/api/reliability/jobs/${jobId}/cancel`, function() {
        fetchReliabilityJobs();
    }).fail(function(xhr) {
        const message = xhr.responseJSON?.error || 'Unable to cancel job';
        alert(message);
    });
}

function scheduleReliabilityPoll() {
    reliabilityPollTimer = setTimeout(fetchReliabilityJobs, 2000);
}

function fetchReliabilityJobs() {
    $.get('/api/reliability/jobs', function(data) {
        reliabilityJobs = data.jobs || [];
        renderReliabilityJobs(reliabilityJobs);
        updateQueueTimestamp();
        scheduleReliabilityPoll();
    }).fail(function() {
        scheduleReliabilityPoll();
    });
}

function scheduleMetricsPoll() {
    if (reliabilityMetricsTimer) {
        clearTimeout(reliabilityMetricsTimer);
    }
    reliabilityMetricsTimer = setTimeout(fetchReliabilityMetrics, METRICS_POLL_INTERVAL);
}

function fetchReliabilityMetrics() {
    $.get('/api/reliability/metrics', function(data) {
        renderReliabilityMetrics(data);
        scheduleMetricsPoll();
    }).fail(function() {
        scheduleMetricsPoll();
    });
}

function renderReliabilityJobs(jobs) {
    if (!Array.isArray(jobs)) jobs = [];

    jobs.sort((a, b) => (a.enqueued_at || 0) - (b.enqueued_at || 0));

    const queue = $('#reliability-queue');
    queue.empty();

    if (!jobs.length) {
        $('#queue-empty').removeClass('d-none').show();
    } else {
        $('#queue-empty').addClass('d-none').hide();
    }

    let queued = 0;
    let running = 0;
    let completed = 0;
    let errors = 0;

    jobs.forEach(job => {
        queue.append(buildReliabilityCard(job));
        if (job.status === 'queued') queued += 1;
        else if (job.status === 'running') running += 1;
        else if (job.status === 'completed') completed += 1;
        else if (job.status === 'error') errors += 1;
    });

    $('#stat-queued').text(queued);
    $('#stat-running').text(running);
    $('#stat-completed').text(completed);
    $('#stat-errors').text(errors);
}

function renderReliabilityMetrics(metrics) {
    reliabilityMetrics = metrics || null;

    const threads = (metrics && metrics.threads) ? metrics.threads : {};
    $('#stat-threads-process').text(formatNumber(threads.process));
    $('#stat-threads-python').text(formatNumber(threads.python));

    const cpu = (metrics && metrics.cpu) ? metrics.cpu : {};
    $('#stat-cpu-process').text(formatPercent(cpu.process_percent));
    $('#stat-cpu-system').text(formatPercent(cpu.system_percent));
    updateProgressBar('#bar-cpu-process', cpu.process_percent);
    updateProgressBar('#bar-cpu-system', cpu.system_percent);

    const memory = (metrics && metrics.memory) ? metrics.memory : {};
    $('#stat-mem-process').text(formatMegabytes(memory.process_mb));
    $('#stat-mem-process-pct').text(formatPercent(memory.process_percent));
    if (memory.system_percent !== undefined && memory.system_used_gb !== undefined && memory.system_total_gb !== undefined) {
        $('#stat-mem-system').text(
            `${formatPercent(memory.system_percent)} · ${memory.system_used_gb}/${memory.system_total_gb} GB`
        );
    } else {
        $('#stat-mem-system').text('—');
    }
    updateProgressBar('#bar-mem-process', memory.process_percent);
    updateProgressBar('#bar-mem-system', memory.system_percent);

    const queue = (metrics && metrics.queue) ? metrics.queue : {};
    if (queue.queued !== undefined) $('#stat-queued').text(queue.queued);
    if (queue.running !== undefined) $('#stat-running').text(queue.running);
    if (queue.completed !== undefined) $('#stat-completed').text(queue.completed);
    if (queue.errors !== undefined) $('#stat-errors').text(queue.errors);
}

function buildReliabilityCard(job) {
    const snapshot = job.snapshot || {};
    const devices = snapshot.devices || {};
    const queuePosition = job.queue_position;

    const percent = typeof snapshot.percent_complete === 'number'
        ? snapshot.percent_complete
        : (job.status === 'queued' ? 0 : 100);

    const runtime = snapshot.runtime ? formatDuration(snapshot.runtime) : '—';
    const alive = devices.alive ?? '—';
    const scanned = devices.scanned ?? '—';
    const total = devices.total ?? '—';
    const openPorts = snapshot.open_ports ?? '—';

    const actions = [];
    if (job.status === 'queued') {
        actions.push(`<button class="btn btn-sm btn-outline-secondary btn-cancel-job" data-job="${job.id}">Cancel</button>`);
    }
    if (snapshot.scan_id) {
        actions.push(`<a class="btn btn-sm btn-outline-primary" target="_blank" href="/scan/${snapshot.scan_id}">View Scan</a>`);
    }

    const subtitle = `${job.config.subnet || '—'} · Ports: ${job.config.port_list || '—'}`;
    const positionLabel = job.status === 'queued'
        ? (queuePosition === 0 ? 'Next up' : `In queue (#${queuePosition + 1})`)
        : job.status === 'running' ? 'In progress' : 'Finished';

    return `
    <div class="reliability-job-card status-${job.status}">
        <div class="reliability-job-header">
            <div>
                <div class="job-label">${job.label || 'Unnamed run'}</div>
                <div class="job-subtitle">${subtitle}</div>
            </div>
            <div class="text-end">
                <span class="badge bg-${statusColor(job.status)}">${formatStatus(job.status)}</span>
                <div class="queue-position">${positionLabel}</div>
            </div>
        </div>
        <div class="progress reliability-progress">
            <div class="progress-bar" role="progressbar" style="width: ${percent}%">${percent}%</div>
        </div>
        <div class="job-stats">
            <div>
                <small>Devices Alive</small>
                <span>${alive} / ${total}</span>
            </div>
            <div>
                <small>Devices Scanned</small>
                <span>${scanned}</span>
            </div>
            <div>
                <small>Open Ports</small>
                <span>${openPorts}</span>
            </div>
            <div>
                <small>Runtime</small>
                <span>${runtime}</span>
            </div>
        </div>
        ${actions.length ? `<div class="job-actions">${actions.join('')}</div>` : ''}
    </div>`;
}

function updateQueueTimestamp() {
    const stamp = new Date().toLocaleTimeString();
    $('#queue-updated').text(`Updated ${stamp}`);
}

function formatStatus(status) {
    switch (status) {
        case 'running':
            return 'Running';
        case 'completed':
            return 'Complete';
        case 'error':
            return 'Error';
        case 'cancelled':
            return 'Cancelled';
        default:
            return 'Queued';
    }
}

function statusColor(status) {
    switch (status) {
        case 'running':
            return 'primary';
        case 'completed':
            return 'success';
        case 'error':
            return 'danger';
        case 'cancelled':
            return 'secondary';
        default:
            return 'warning';
    }
}

function formatDuration(seconds) {
    if (!seconds && seconds !== 0) return '—';
    const sec = Math.floor(seconds);
    const mins = Math.floor(sec / 60);
    const rem = sec % 60;
    return `${String(mins).padStart(2, '0')}:${String(rem).padStart(2, '0')}`;
}

function formatPercent(value) {
    if (value === undefined || value === null || Number.isNaN(value)) return '—';
    return `${Number(value).toFixed(1)}%`;
}

function formatNumber(value) {
    if (value === undefined || value === null || Number.isNaN(value)) return '—';
    return value;
}

function formatMegabytes(value) {
    if (value === undefined || value === null || Number.isNaN(value)) return '—';
    return Number(value).toFixed(1);
}

function updateProgressBar(selector, value) {
    const bar = $(selector);
    if (!bar.length) return;
    const track = bar.closest('.metric-progress');
    if (!track.length) return;
    if (value === undefined || value === null || Number.isNaN(value)) {
        bar.css('width', '0%');
        track.attr('aria-valuenow', 0);
        return;
    }
    const clamped = Math.max(0, Math.min(100, Number(value)));
    bar.css('width', `${clamped}%`);
    track.attr('aria-valuenow', clamped);
}
