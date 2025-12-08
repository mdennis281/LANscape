"""API endpoints for reliability testing UI."""

from flask import jsonify, request

from lanscape.core.reliability_queue import reliability_queue
from lanscape.core.scan_config import ScanConfig
from lanscape.core.system_stats import collect_runtime_metrics
from lanscape.ui.blueprints.api import api_bp


@api_bp.route('/api/reliability/jobs', methods=['GET'])
def list_reliability_jobs():
    """Return the current queue of reliability jobs."""
    return jsonify({'jobs': reliability_queue.list_jobs()})


@api_bp.route('/api/reliability/metrics', methods=['GET'])
def reliability_metrics():
    """Return system metrics for the reliability dashboard."""
    metrics = collect_runtime_metrics({'queue': reliability_queue.get_status_counts()})
    return jsonify(metrics)


@api_bp.route('/api/reliability/jobs', methods=['POST'])
def enqueue_reliability_job():
    """Queue one or more scans for sequential reliability testing."""
    payload = request.get_json(force=True) or {}
    config_data = payload.get('config') or payload.get('scan_config') or payload
    if not config_data:
        return jsonify({'error': 'config payload required'}), 400

    label = payload.get('label')
    repeat_raw = int(payload.get('count') or payload.get('runs') or 1)
    repeat = max(1, min(repeat_raw, 50))

    try:
        config = ScanConfig.from_dict(config_data)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return jsonify({'error': f'Invalid configuration: {exc}'}), 400

    jobs = reliability_queue.enqueue(config, label=label, repeat=repeat)
    return jsonify({'jobs': [job.summary() for job in jobs]}), 201


@api_bp.route('/api/reliability/jobs/<job_id>', methods=['GET'])
def get_reliability_job(job_id: str):
    """Return a single job detail."""
    job = reliability_queue.get_job(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404
    return jsonify(job)


@api_bp.route('/api/reliability/jobs/<job_id>/cancel', methods=['POST'])
def cancel_reliability_job(job_id: str):
    """Cancel a queued job."""
    success = reliability_queue.cancel(job_id)
    if not success:
        return jsonify({'error': 'job cannot be cancelled'}), 400
    return jsonify({'success': True})
