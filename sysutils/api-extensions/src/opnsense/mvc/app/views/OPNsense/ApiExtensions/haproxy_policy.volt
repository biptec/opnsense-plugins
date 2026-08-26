<script>
$(document).ready(function() {
    const apiBase = '/api/api_extensions/haproxy_policy';
    let currentPolicies = [];
    let pendingAssignments = {};
    let overviewGrid = null;

    function policyById(policyId) {
        return currentPolicies.find(function(policy) { return policy.id === policyId; }) || null;
    }

    function populatePolicySelect(select, selected, includeEmpty, includeDescription) {
        select.empty();
        if (includeEmpty) {
            select.append($('<option>').attr('value', '').text('{{ lang._("Select policy") }}'));
        }
        currentPolicies.forEach(function(policy) {
            const label = includeDescription && policy.description ? policy.id + ' — ' + policy.description : policy.id;
            select.append($('<option>').attr('value', policy.id).text(label));
        });
        select.val(selected || '');
        const selectedPolicy = policyById(selected || '');
        if (selectedPolicy) {
            select.attr('title', selectedPolicy.description ? selectedPolicy.id + ' — ' + selectedPolicy.description : selectedPolicy.id);
        } else {
            select.removeAttr('title');
        }
    }

    function populateFilters() {
        const filter = $('#haproxy-policy-filter');
        const previous = filter.val() || '__all';
        filter.empty();
        filter.append($('<option>').attr('value', '__all').text('{{ lang._("All policies") }}'));
        currentPolicies.forEach(function(policy) {
            const label = policy.description ? policy.id + ' — ' + policy.description : policy.id;
            filter.append($('<option>').attr('value', policy.id).text(label));
        });
        filter.append($('<option>').attr('value', '__unassigned').text('{{ lang._("Unassigned") }}'));
        filter.val(filter.find('option[value="' + previous + '"]').length ? previous : '__all');
        if (filter.hasClass('selectpicker')) {
            filter.selectpicker('refresh');
        }
    }

    function assignmentFailed(data) {
        BootstrapDialog.show({
            type: BootstrapDialog.TYPE_DANGER,
            title: '{{ lang._("HAProxy policy assignment failed") }}',
            message: (data && data.message) ? data.message : JSON.stringify(data || {})
        });
    }

    function behaviorElement(policyId) {
        const policy = policyById(policyId);
        if (!policy) {
            return $('<span>').addClass('label label-warning').text('{{ lang._("Unassigned") }}')[0];
        }
        return $('<span>')
            .addClass('label ' + (policy.synchronize ? 'label-success' : 'label-default'))
            .text(policy.synchronize ? '{{ lang._("Synchronize") }}' : '{{ lang._("Local only") }}')[0];
    }

    function effectivePolicy(row) {
        return Object.prototype.hasOwnProperty.call(pendingAssignments, row.object_key) ?
            pendingAssignments[row.object_key] : (row.policy_id || '');
    }

    function updatePendingState() {
        const count = Object.keys(pendingAssignments).length;
        $('#btn-haproxy-policy-save-changes').prop('disabled', count === 0);
        $('#haproxy-policy-pending-count')
            .text(count ? count + ' {{ lang._("unsaved change(s)") }}' : '')
            .toggle(count > 0);
    }

    function updateBulkState() {
        const selectedCount = overviewGrid ? overviewGrid.bootgrid('getTable').getSelectedData().length : 0;
        const bulkPolicy = $('#haproxy-policy-bulk-policy');
        const hasSelection = selectedCount > 0;
        bulkPolicy.prop('disabled', !hasSelection);
        $('#btn-haproxy-policy-bulk-apply').prop('disabled', !hasSelection || !bulkPolicy.val());
        $('#haproxy-policy-selected-count')
            .text(hasSelection ? selectedCount + ' {{ lang._("selected") }}' : '')
            .toggle(hasSelection);
        if (bulkPolicy.hasClass('selectpicker')) {
            bulkPolicy.selectpicker('refresh');
        }
    }

    function stageAssignment(objectKey, originalPolicy, policyId) {
        if (policyId === (originalPolicy || '')) {
            delete pendingAssignments[objectKey];
        } else {
            pendingAssignments[objectKey] = policyId;
        }
        updatePendingState();
        if (overviewGrid) {
            const table = overviewGrid.bootgrid('getTable');
            const row = table.getRow(objectKey);
            if (row) row.reformat();
        }
    }

    function policyFormatter(column, row) {
        const policyId = effectivePolicy(row);
        if (row.owner === 'ha_peer' || row.owner === 'stale') {
            const policy = policyById(policyId);
            return $('<span>').addClass(row.owner === 'stale' ? 'text-danger' : 'text-muted').text(policy ? policy.id : '{{ lang._("Unassigned") }}')[0];
        }
        const select = $('<select>')
            .addClass('form-control input-sm haproxy-policy-row-policy')
            .attr('data-object-key', row.object_key || '');
        populatePolicySelect(select, policyId, true, false);
        select.on('click', function(event) { event.stopPropagation(); });
        select.on('change', function(event) {
            event.stopPropagation();
            stageAssignment(row.object_key, row.policy_id || '', $(this).val());
        });
        return $('<div>').addClass('haproxy-policy-select-wrap').append(select)[0];
    }

    function syncFormatter(column, row) {
        return behaviorElement(effectivePolicy(row));
    }

    function ownerFormatter(column, row) {
        if (row.owner === 'ha_peer') {
            return $('<span>').addClass('text-muted').text('{{ lang._("HA peer") }}')[0];
        }
        if (row.owner === 'stale') {
            return $('<span>').addClass('label label-danger').text('{{ lang._("Stale assignment") }}')[0];
        }
        if (row.owner === 'unassigned') {
            return $('<span>').addClass('label label-warning').text('{{ lang._("Unassigned") }}')[0];
        }
        return '{{ lang._("Local") }}';
    }

    function commandsFormatter(column, row) {
        if (row.owner !== 'stale' || !row.assignment_uuid) {
            return '';
        }
        return $('<button>')
            .attr('type', 'button')
            .addClass('btn btn-xs btn-default bootgrid-tooltip haproxy-policy-delete-stale')
            .attr('data-assignment-uuid', row.assignment_uuid)
            .attr('data-object-name', row.object_name)
            .attr('title', '{{ lang._("Remove stale policy assignment") }}')
            .append($('<span>').addClass('fa fa-fw fa-trash-o'))[0];
    }

    function typeFormatter(column, row) {
        return row.object_type === 'server' ? '{{ lang._("Server") }}' : '{{ lang._("Backend") }}';
    }

    function savePendingAssignments() {
        if (!Object.keys(pendingAssignments).length) {
            return;
        }
        ajaxCall(apiBase + '/batchAssign', {assignments: pendingAssignments}, function(data) {
            if (data && data.result === 'saved') {
                pendingAssignments = {};
                updatePendingState();
                refreshOverview();
            } else {
                assignmentFailed(data);
            }
        });
    }

    function initOverviewGrid() {
        overviewGrid = $('#grid-haproxy-policy-overview').UIBootgrid({
            search: apiBase + '/searchOverview',
            options: {
                responsive: true,
                disableScroll: true,
                rowCount: [20, 50, 100, -1],
                requestHandler: function(request) {
                    const policyFilter = $('#haproxy-policy-filter').val();
                    const typeFilter = $('#haproxy-policy-type-filter').val();
                    if (policyFilter && policyFilter !== '__all') {
                        request.policy_id = policyFilter;
                    }
                    if (typeFilter && typeFilter !== '__all') {
                        request.object_type = typeFilter;
                    }
                    return request;
                },
                selection: true,
                multiSelect: true,
                formatters: {
                    type: typeFormatter,
                    policy: policyFormatter,
                    sync: syncFormatter,
                    owner: ownerFormatter,
                    commands: commandsFormatter
                }
            },
            tabulatorOptions: {
                selectableRowsCheck: function(row) {
                    return row.getData().owner === 'local' || row.getData().owner === 'unassigned';
                },
                rowFormatter: function(row) {
                    const element = $(row.getElement());
                    element.toggleClass(
                        'haproxy-policy-pending-row',
                        Object.prototype.hasOwnProperty.call(pendingAssignments, row.getData().object_key)
                    );
                    if (row.getData().owner === 'ha_peer') {
                        element.addClass('haproxy-policy-peer-row');
                    }
                }
            }
        });

        $('#haproxy-policy-filter-container').detach()
            .insertBefore('#grid-haproxy-policy-overview-header .search')
            .show();
        $('#haproxy-policy-filter').selectpicker('refresh');
        $('#haproxy-policy-type-filter').selectpicker('refresh');
        $('#haproxy-policy-bulk-policy').selectpicker('refresh');
        $('#grid-haproxy-policy-overview')
            .on('selected.rs.jquery.bootgrid deselected.rs.jquery.bootgrid loaded.rs.jquery.bootgrid', updateBulkState);
        $('#haproxy-policy-bulk-policy').on('changed.bs.select change', updateBulkState);
        bindHaproxyNativeRefresh();
        updateBulkState();
    }

    function refreshOverview() {
        ajaxGet(apiBase + '/overview', {}, function(data) {
            const status = $('#haproxy-policy-ha-status');
            const warning = $('#haproxy-policy-warning');

            if (!data || data.status !== 'ok') {
                status.removeClass('label-success label-default').addClass('label-danger').text('{{ lang._("Unavailable") }}');
                warning.removeClass('alert-warning alert-info').addClass('alert-danger')
                    .text((data && data.message) ? data.message : '{{ lang._("Unable to read HAProxy policy state.") }}').show();
                return;
            }

            status.removeClass('label-danger label-default')
                .addClass(data.ha_service_enabled ? 'label-success' : 'label-default')
                .text(data.ha_service_enabled ? '{{ lang._("Enabled") }}' : '{{ lang._("Disabled") }}');

            currentPolicies = data.policies || [];
            populateFilters();
            const bulkPolicy = $('#haproxy-policy-bulk-policy');
            const previousBulkPolicy = bulkPolicy.val();
            populatePolicySelect(bulkPolicy, previousBulkPolicy, true, true);
            if (bulkPolicy.hasClass('selectpicker')) {
                bulkPolicy.selectpicker('refresh');
            }

            if (data.stale_assignments > 0) {
                warning.removeClass('alert-info alert-warning').addClass('alert-danger')
                    .text(data.stale_assignments + ' {{ lang._("stale HAProxy policy assignment(s) reference objects that no longer exist. Remove the stale assignment(s) before synchronization can continue.") }}')
                    .show();
            } else if (data.unassigned > 0) {
                warning.removeClass('alert-info alert-danger').addClass('alert-warning')
                    .text(data.unassigned + ' {{ lang._("HAProxy server/backend object(s) have no policy assignment. HAProxy synchronization is fail-closed until every local server and backend is assigned.") }}')
                    .show();
            } else {
                warning.hide().text('');
            }

            if (overviewGrid === null) {
                initOverviewGrid();
            } else {
                overviewGrid.bootgrid('reload');
            }
        });
    }

    $(document).on('changed.bs.select', '#haproxy-policy-filter, #haproxy-policy-type-filter', function() {
        if (overviewGrid) {
            overviewGrid.bootgrid('reload');
        }
    });
    function refreshHaproxySafely() {
        if (!Object.keys(pendingAssignments).length) {
            refreshOverview();
            return;
        }
        stdDialogConfirm(
            '{{ lang._("Discard unsaved changes?") }}',
            '{{ lang._("Refreshing will discard the HAProxy policy changes that have not been saved yet.") }}',
            '{{ lang._("Discard") }}',
            '{{ lang._("Cancel") }}',
            function() {
                pendingAssignments = {};
                updatePendingState();
                refreshOverview();
            }
        );
    }

    function bindHaproxyNativeRefresh() {
        $('#grid-haproxy-policy-overview-refresh-button')
            .off('click')
            .on('click', refreshHaproxySafely);
    }
    $(document).on('click', '#btn-haproxy-policy-bulk-apply', function() {
        const policyId = $('#haproxy-policy-bulk-policy').val();
        const selected = overviewGrid ? overviewGrid.bootgrid('getTable').getSelectedData() : [];
        if (!selected.length || !policyId) {
            assignmentFailed({message: '{{ lang._("Select at least one HAProxy object and a policy.") }}'});
            return;
        }
        selected.forEach(function(row) {
            stageAssignment(row.object_key, row.policy_id || '', policyId);
        });
        updateBulkState();
    });
    $(document).on('click', '#btn-haproxy-policy-save-changes', savePendingAssignments);
    $(document).on('click', '.haproxy-policy-delete-stale', function(event) {
        event.preventDefault();
        event.stopPropagation();
        const button = $(this);
        const assignmentUuid = button.attr('data-assignment-uuid');
        const objectName = button.attr('data-object-name') || '';
        if (!assignmentUuid) {
            return;
        }
        stdDialogConfirm(
            '{{ lang._("Remove stale policy assignment?") }}',
            '{{ lang._("This removes only the HA sync policy metadata for the missing HAProxy object. It does not delete any HAProxy configuration object.") }}' + (objectName ? ' ' + objectName : ''),
            '{{ lang._("Remove assignment") }}',
            '{{ lang._("Cancel") }}',
            function() {
                ajaxCall(apiBase + '/delAssignment/' + encodeURIComponent(assignmentUuid), {}, function(data) {
                    if (data && data.result === 'deleted') {
                        pendingAssignments = {};
                        updatePendingState();
                        refreshOverview();
                    } else {
                        assignmentFailed(data);
                    }
                });
            }
        );
    });
    $(document).on('settings-changed', function() {
        pendingAssignments = {};
        updatePendingState();
        refreshOverview();
    });
    refreshOverview();
});
</script>

<style>
.haproxy-policy-select-wrap {
    display: flex;
    align-items: center;
    width: 100%;
    min-height: 36px;
    padding: 2px 0;
    box-sizing: border-box;
}
.haproxy-policy-row-policy {
    display: block;
    width: 100%;
    min-width: 120px;
    height: 32px !important;
    min-height: 32px !important;
    line-height: 20px !important;
    padding: 5px 28px 5px 10px !important;
    font-size: 12px;
    box-sizing: border-box;
    vertical-align: middle;
}
#grid-haproxy-policy-overview .tabulator-row .tabulator-cell[tabulator-field="policy_id"] {
    padding-top: 2px;
    padding-bottom: 2px;
    overflow: visible !important;
}
.haproxy-policy-pending-row { background-color: #fcf8e3 !important; }
.haproxy-policy-peer-row { opacity: 0.72; }
#haproxy-policy-filter-container {
    float: none !important;
    display: inline-flex;
    flex: 1 1 360px;
    min-width: 360px;
    max-width: 620px;
    gap: 6px;
}
#haproxy-policy-filter-container .bootstrap-select { width: 100% !important; }
#haproxy-policy-filter-container .bootstrap-select:first-child { flex: 1 1 65%; }
#haproxy-policy-filter-container .bootstrap-select:last-child { flex: 1 1 35%; }
#haproxy-policy-bulk-footer {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-left: 10px;
    vertical-align: middle;
}
#haproxy-policy-bulk-footer .bootstrap-select {
    width: 330px !important;
    min-width: 330px;
}
#haproxy-policy-bulk-footer .bootstrap-select > .dropdown-toggle,
.haproxy-policy-row-policy {
    overflow: visible;
    text-overflow: clip;
}
#haproxy-policy-selected-count,
#haproxy-policy-pending-count { color: #8a6d3b; white-space: nowrap; }
@media (max-width: 1024px) {
    #haproxy-policy-filter-container {
        flex: 1 1 100%;
        min-width: 100%;
        max-width: 100%;
    }
    #haproxy-policy-bulk-footer {
        width: 100%;
        margin: 8px 0 0 0;
        flex-wrap: wrap;
    }
    #haproxy-policy-bulk-footer .bootstrap-select {
        width: 100% !important;
        min-width: 220px;
        max-width: 100%;
    }
}
</style>

<div id="interface-policy-haproxy-tab" class="tab-pane fade">
    <div class="hidden">
        <div id="haproxy-policy-filter-container" class="btn-group">
            <select id="haproxy-policy-filter"
                    class="selectpicker"
                    data-live-search="true"
                    data-size="20"
                    data-container="body"
                    data-width="100%"
                    title="{{ lang._('All policies') }}">
            </select>
            <select id="haproxy-policy-type-filter"
                    class="selectpicker"
                    data-container="body"
                    data-width="100%">
                <option value="__all">{{ lang._('All object types') }}</option>
                <option value="server">{{ lang._('Servers') }}</option>
                <option value="backend">{{ lang._('Backends') }}</option>
            </select>
        </div>
    </div>

    <table id="grid-haproxy-policy-overview" class="table table-condensed table-hover table-striped" style="visibility: hidden">
        <thead><tr>
            <th data-column-id="uuid" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
            <th data-column-id="assignment_uuid" data-visible="false">{{ lang._('Assignment ID') }}</th>
            <th data-column-id="object_type" data-type="string" data-formatter="type" data-width="100">{{ lang._('Type') }}</th>
            <th data-column-id="object_name" data-type="string">{{ lang._('Name') }}</th>
            <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
            <th data-column-id="details" data-type="string">{{ lang._('Target / Relations') }}</th>
            <th data-column-id="policy_id" data-type="string" data-formatter="policy" data-width="150">{{ lang._('HA Policy') }}</th>
            <th data-column-id="synchronize" data-type="string" data-formatter="sync" data-width="120">{{ lang._('Sync') }}</th>
            <th data-column-id="owner" data-type="string" data-formatter="owner" data-width="120">{{ lang._('Managed By') }}</th>
            <th data-column-id="commands" data-formatter="commands" data-sortable="false" data-width="80">{{ lang._('Commands') }}</th>
        </tr></thead>
        <tbody></tbody>
        <tfoot><tr>
            <td></td>
            <td>
                <div id="haproxy-policy-bulk-footer">
                    <span id="haproxy-policy-selected-count" style="display:none;"></span>
                    <select id="haproxy-policy-bulk-policy"
                            class="selectpicker"
                            data-live-search="true"
                            data-size="20"
                            data-width="330px"
                            data-container="body"
                            title="{{ lang._('Set HA policy') }}"
                            disabled>
                    </select>
                    <button id="btn-haproxy-policy-bulk-apply"
                            type="button"
                            class="btn btn-xs btn-default"
                            data-toggle="tooltip"
                            data-placement="top"
                            title="{{ lang._('Set the selected HA policy on checked HAProxy objects. Changes are staged until Save changes is pressed.') }}"
                            disabled>
                        <i class="fa fa-fw fa-tag"></i>
                        {{ lang._('Set policy') }}
                    </button>
                </div>
            </td>
        </tr></tfoot>
    </table>

    <section id="haproxy-policy-overview-actions" class="grid-bottom-reserve __mt">
        <div class="alert content-box" style="display: flex; align-items: center; gap: 8px; margin-bottom: 0;">
            <button id="btn-haproxy-policy-save-changes" type="button" class="btn btn-primary __mr" disabled>
                <i class="fa fa-fw fa-save"></i>
                {{ lang._('Save changes') }}
            </button>
            <div id="haproxy-policy-pending-count" style="display:none;"></div>
        </div>
    </section>

    <div class="interface-policy-help">
        <p class="help-block">
            {{ lang._('HAProxy server and backend synchronization is selected only by explicit HA policy assignment. Frontends, global HAProxy settings, certificates and other node-local objects are not replaced. Backend server references are rebuilt on the peer by semantic server name and the peer keeps its own local MVC UUIDs.') }}
        </p>
        <div id="haproxy-policy-warning" class="alert alert-warning" style="display:none;"></div>
    </div>
</div>
