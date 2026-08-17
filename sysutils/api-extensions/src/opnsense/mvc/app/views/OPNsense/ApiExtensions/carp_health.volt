<script>
$(document).ready(function() {
    const apiBase = '/api/api_extensions/carp_health';

    function showMessage(kind, text) {
        const box = $('#carp-health-message');
        box.removeClass('alert-success alert-danger alert-warning alert-info')
           .addClass('alert-' + kind).text(text).show();
    }

    function setBadge(id, text, kind) {
        $('#' + id).removeClass('label-default label-success label-danger label-warning label-info')
            .addClass('label-' + kind).text(text);
    }

    function refreshStatus() {
        ajaxGet(apiBase + '/status', {}, function(data) {
            if (!data || data.status !== 'ok') {
                setBadge('status-enabled', 'Unknown', 'warning');
                setBadge('status-running', 'Unknown', 'warning');
                setBadge('status-ready', 'Unknown', 'warning');
                setBadge('status-healthy', 'Unknown', 'warning');
                setBadge('status-control', 'Unknown', 'warning');
                showMessage('danger', '{{ lang._("Unable to read CARP health runtime status.") }}');
                return;
            }

            setBadge('status-enabled', data.enabled ? 'Enabled' : 'Disabled', data.enabled ? 'success' : 'default');
            setBadge('status-running', data.running ? 'Running' : 'Stopped', data.running ? 'success' : 'danger');
            setBadge('status-ready', data.ready ? 'Ready' : 'Initializing', data.ready ? 'success' : 'warning');
            if (!data.enabled) {
                setBadge('status-healthy', 'Disabled', 'default');
                setBadge('status-control', 'Disabled', 'default');
            } else if (!data.ready) {
                setBadge('status-healthy', 'Unknown', 'warning');
                setBadge('status-control', data.control_ok ? 'Applied' : 'Pending', data.control_ok ? 'success' : 'warning');
            } else {
                setBadge('status-healthy', data.healthy ? 'Healthy' : 'Degraded', data.healthy ? 'success' : 'danger');
                setBadge('status-control', data.control_ok ? 'Applied' : 'Error', data.control_ok ? 'success' : 'danger');
            }

            $('#status-signature').text(data.config_signature || '-');
            $('#status-timestamp').text(data.timestamp ? new Date(Number(data.timestamp) * 1000).toLocaleString() : '-');

            function displayValue(value) {
                if (value === null || value === undefined || value === '') return '-';
                if (Array.isArray(value)) return value.length ? value.join(', ') : '-';
                return String(value);
            }

            const tbody = $('#runtime-checks tbody').empty();
            const checks = Array.isArray(data.checks) ? data.checks : [];
            if (checks.length === 0) {
                $('<tr>').append($('<td>').attr('colspan', 13).addClass('text-muted')
                    .text('{{ lang._("No runtime health checks are active.") }}')).appendTo(tbody);
            } else {
                checks.forEach(function(check) {
                    const row = $('<tr>');
                    const targets = Array.isArray(check.vhid_targets) ? check.vhid_targets : [];
                    const targetStates = Array.isArray(check.vhid_states) ? check.vhid_states : [];
                    const desired = targetStates.map(function(item) {
                        return (item.interface || '?') + ':' + (item.vhid || '?') + '=' + displayValue(item.desired_advskew);
                    });
                    const carpStates = targetStates.map(function(item) {
                        return (item.interface || '?') + ':' + (item.vhid || '?') + '=' + (item.carp_state || 'UNKNOWN');
                    });
                    let scope = 'Legacy Global';
                    if (check.scope === 'interface') scope = 'Auto Interface';
                    if (check.scope === 'all_carp') scope = 'Auto All CARP';
                    if (check.scope === 'vhid') scope = 'Explicit VHID';
                    if (check.scope === 'vhid_group') scope = 'Explicit VHID Group';
                    $('<td>').text(check.name || '').appendTo(row);
                    $('<td>').text(check.interface || '').appendTo(row);
                    $('<td>').text(check.target || '').appendTo(row);
                    $('<td>').text(scope).appendTo(row);
                    $('<td>').text(targets.length ? targets.join(', ') : (check.vhid || '-')).appendTo(row);
                    $('<td>').text(displayValue(check.failure_advskew)).appendTo(row);
                    $('<td>').text(carpStates.length ? carpStates.join(', ') : (check.carp_state || '-')).appendTo(row);
                    $('<td>').text(desired.length ? desired.join(', ') : '-').appendTo(row);
                    $('<td>').text(displayValue(check.configured_advskew)).appendTo(row);
                    $('<td>').text(displayValue(check.current_advskew)).appendTo(row);
                    $('<td>').append($('<span>').addClass('label ' + (check.healthy ? 'label-success' : 'label-danger'))
                        .text(check.healthy ? 'Healthy' : 'Failed')).appendTo(row);
                    $('<td>').text(check.failures === undefined ? 0 : check.failures).appendTo(row);
                    $('<td>').text(check.successes === undefined ? 0 : check.successes).appendTo(row);
                    row.appendTo(tbody);
                });
            }

            const routeBody = $('#runtime-routes tbody').empty();
            const routes = Array.isArray(data.routes) ? data.routes : [];
            if (routes.length === 0) {
                $('<tr>').append($('<td>').attr('colspan', 8).addClass('text-muted')
                    .text('{{ lang._("No conditional fallback routes are configured.") }}')).appendTo(routeBody);
            } else {
                routes.forEach(function(route) {
                    const row = $('<tr>');
                    $('<td>').text(route.check || route.check_uuid || '').appendTo(row);
                    $('<td>').text(route.family === 'inet6' ? 'IPv6' : 'IPv4').appendTo(row);
                    $('<td>').text(route.destination || '').appendTo(row);
                    $('<td>').text(route.gateway || '').appendTo(row);
                    $('<td>').text(route.desired_installed ? 'Installed' : 'Absent').appendTo(row);
                    $('<td>').text(route.installed ? 'Yes' : 'No').appendTo(row);
                    $('<td>').text(route.managed ? 'Yes' : 'No').appendTo(row);
                    $('<td>').append($('<span>').addClass('label ' + (route.control_ok ? 'label-success' : 'label-danger'))
                        .text(route.control_ok ? 'Applied' : 'Failed')).appendTo(row);
                    row.appendTo(routeBody);
                });
            }
        });
    }

    function applyConfiguration(progressSelector, done) {
        const progress = $(progressSelector);
        progress.addClass('fa fa-spinner fa-pulse');
        ajaxCall(apiBase + '/reconfigure', {}, function(data) {
            progress.removeClass('fa fa-spinner fa-pulse');
            if (data && data.status === 'ok') {
                $('#pending-checks').hide();
                showMessage('success', '{{ lang._("CARP health configuration applied.") }}');
                refreshStatus();
                if (done) done(true);
            } else {
                showMessage('danger', '{{ lang._("Failed to apply CARP health configuration.") }}');
                if (done) done(false);
            }
        });
    }

    mapDataToFormUI({'frm_carp_health_settings': apiBase + '/get'}).done(function() {
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
    });

    $('#grid-carp-health-checks').UIBootgrid({
        search: apiBase + '/searchCheck',
        get: apiBase + '/getCheck/',
        set: apiBase + '/setCheck/',
        add: apiBase + '/addCheck',
        del: apiBase + '/delCheck/'
    });

    $('#btn_save_carp_health').click(function() {
        $('#frm_carp_health_settings_progress').addClass('fa fa-spinner fa-pulse');
        saveFormToEndpoint(apiBase + '/set', 'frm_carp_health_settings', function() {
            $('#frm_carp_health_settings_progress').removeClass('fa fa-spinner fa-pulse');
            applyConfiguration('#carp-health-apply-progress');
        });
    });

    $('#btn_apply_checks').click(function() {
        applyConfiguration('#carp-health-apply-progress');
    });

    $('#btn_refresh_status').click(refreshStatus);
    $('a[href="#runtime-status"]').on('shown.bs.tab', refreshStatus);

    $(document).on('settings-changed.carp-health', function() {
        $('#pending-checks').show();
    });

    refreshStatus();
    window.setInterval(function() {
        if ($('#runtime-status').hasClass('active')) refreshStatus();
    }, 3000);
});
</script>

<div id="carp-health-message" class="alert" style="display:none"></div>

<ul class="nav nav-tabs" data-tabs="tabs" id="carp-health-tabs">
    <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#health-checks">{{ lang._('Health Checks') }}</a></li>
    <li><a data-toggle="tab" href="#runtime-status">{{ lang._('Runtime Status') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="settings" class="tab-pane fade in active">
        <div class="content-box">
            {{ partial('layout_partials/base_form', ['fields': settingsForm, 'id': 'frm_carp_health_settings', 'apply_btn_id': 'btn_save_carp_health']) }}
        </div>
        <div class="alert alert-info">
            {{ lang._('CARP health monitoring is fail-closed. New checks automatically discover CARP VHIDs from OPNsense: use Probe Interface for normal per-VLAN health and All CARP for upstream/WAN health. Explicit VHID and VHID Group remain available as advanced overrides; Legacy Global keeps native global demotion behavior.') }}
        </div>
    </div>

    <div id="health-checks" class="tab-pane fade in">
        <div id="pending-checks" class="alert alert-warning" style="display:none">
            {{ lang._('Health-check configuration changed. Apply the staged changes when the complete check set is ready.') }}
        </div>
        <table id="grid-carp-health-checks" class="table table-condensed table-hover table-striped table-responsive" data-editDialog="DialogCarpHealthCheck">
            <thead>
                <tr>
                    <th data-column-id="enabled" data-type="string" data-formatter="boolean">{{ lang._('Enabled') }}</th>
                    <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                    <th data-column-id="interface" data-type="string">{{ lang._('Interface') }}</th>
                    <th data-column-id="target" data-type="string">{{ lang._('IPv4 Target') }}</th>
                    <th data-column-id="scope" data-type="string">{{ lang._('CARP Scope') }}</th>
                    <th data-column-id="vhid" data-type="numeric">{{ lang._('VHID') }}</th>
                    <th data-column-id="vhid_targets" data-type="string">{{ lang._('Resolved VHID Targets') }}</th>
                    <th data-column-id="failure_advskew" data-type="numeric">{{ lang._('Failure advskew') }}</th>
                    <th data-column-id="commands" data-width="100" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
                    <th data-column-id="uuid" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td><button data-action="add" type="button" class="btn btn-xs btn-default"><span class="fa fa-plus"></span></button></td>
                </tr>
            </tfoot>
        </table>
        <div class="text-right">
            <button id="btn_apply_checks" type="button" class="btn btn-primary">
                <i id="carp-health-apply-progress"></i> {{ lang._('Apply Changes') }}
            </button>
        </div>
    </div>

    <div id="runtime-status" class="tab-pane fade in">
        <div class="content-box">
            <div class="row"><div class="col-sm-3"><strong>{{ lang._('Monitoring') }}</strong></div><div class="col-sm-9"><span id="status-enabled" class="label label-default">Unknown</span></div></div>
            <div class="row"><div class="col-sm-3"><strong>{{ lang._('Monitor process') }}</strong></div><div class="col-sm-9"><span id="status-running" class="label label-default">Unknown</span></div></div>
            <div class="row"><div class="col-sm-3"><strong>{{ lang._('Configuration state') }}</strong></div><div class="col-sm-9"><span id="status-ready" class="label label-default">Unknown</span></div></div>
            <div class="row"><div class="col-sm-3"><strong>{{ lang._('Overall health') }}</strong></div><div class="col-sm-9"><span id="status-healthy" class="label label-default">Unknown</span></div></div>
            <div class="row"><div class="col-sm-3"><strong>{{ lang._('CARP control') }}</strong></div><div class="col-sm-9"><span id="status-control" class="label label-default">Unknown</span></div></div>
            <div class="row"><div class="col-sm-3"><strong>{{ lang._('Configuration signature') }}</strong></div><div class="col-sm-9"><code id="status-signature">-</code></div></div>
            <div class="row"><div class="col-sm-3"><strong>{{ lang._('Last probe update') }}</strong></div><div class="col-sm-9"><span id="status-timestamp">-</span></div></div>
        </div>

        <table id="runtime-checks" class="table table-condensed table-hover table-striped table-responsive">
            <thead><tr>
                <th>{{ lang._('Name') }}</th><th>{{ lang._('Probe Interface') }}</th><th>{{ lang._('Probe Target') }}</th>
                <th>{{ lang._('Scope') }}</th><th>{{ lang._('Resolved VHID Targets') }}</th><th>{{ lang._('Failure advskew') }}</th>
                <th>{{ lang._('CARP State') }}</th><th>{{ lang._('Desired advskew') }}</th>
                <th>{{ lang._('Configured advskew') }}</th><th>{{ lang._('Current advskew') }}</th>
                <th>{{ lang._('Health') }}</th><th>{{ lang._('Failures') }}</th><th>{{ lang._('Successes') }}</th>
            </tr></thead>
            <tbody></tbody>
        </table>

        <h4>{{ lang._('Conditional Fallback Routes') }}</h4>
        <table id="runtime-routes" class="table table-condensed table-hover table-striped table-responsive">
            <thead><tr>
                <th>{{ lang._('Check') }}</th><th>{{ lang._('Family') }}</th><th>{{ lang._('Destination') }}</th><th>{{ lang._('Gateway') }}</th>
                <th>{{ lang._('Desired') }}</th><th>{{ lang._('Installed') }}</th><th>{{ lang._('Managed') }}</th><th>{{ lang._('Control') }}</th>
            </tr></thead>
            <tbody></tbody>
        </table>
        <div class="text-right"><button id="btn_refresh_status" type="button" class="btn btn-default"><span class="fa fa-refresh"></span> {{ lang._('Refresh') }}</button></div>
    </div>
</div>

{{ partial('layout_partials/base_dialog', ['fields': checkForm, 'id': 'DialogCarpHealthCheck', 'label': lang._('Edit CARP Health Check')]) }}
