<script>
$(document).ready(function() {
    const apiBase = '/api/api_extensions/interface_policy';
    let currentPolicies = [];
    let pendingAssignments = {};
    let overviewGrid = null;

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

    function populatePolicyFilter() {
        const filter = $('#interface-policy-filter');
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
            title: '{{ lang._("Policy assignment failed") }}',
            message: (data && data.message) ? data.message : JSON.stringify(data || {})
        });
    }

    function policyById(policyId) {
        return currentPolicies.find(function(policy) { return policy.id === policyId; }) || null;
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
        return Object.prototype.hasOwnProperty.call(pendingAssignments, row.interface) ?
            pendingAssignments[row.interface] : (row.policy_id || '');
    }

    function updatePendingState() {
        const count = Object.keys(pendingAssignments).length;
        $('#btn-interface-policy-save-changes').prop('disabled', count === 0);
        $('#interface-policy-pending-count')
            .text(count ? count + ' {{ lang._("unsaved change(s)") }}' : '')
            .toggle(count > 0);
    }

    function updateBulkState() {
        const selectedCount = overviewGrid ? overviewGrid.bootgrid('getTable').getSelectedData().length : 0;
        const bulkPolicy = $('#interface-policy-bulk-policy');
        const hasSelection = selectedCount > 0;
        bulkPolicy.prop('disabled', !hasSelection);
        $('#btn-interface-policy-bulk-apply').prop('disabled', !hasSelection || !bulkPolicy.val());
        $('#interface-policy-selected-count')
            .text(hasSelection ? selectedCount + ' {{ lang._("selected") }}' : '')
            .toggle(hasSelection);
        if (bulkPolicy.hasClass('selectpicker')) {
            bulkPolicy.selectpicker('refresh');
        }
    }

    function stageAssignment(interfaceId, originalPolicy, policyId) {
        if (policyId === (originalPolicy || '')) {
            delete pendingAssignments[interfaceId];
        } else {
            pendingAssignments[interfaceId] = policyId;
        }
        updatePendingState();
        if (overviewGrid) {
            const table = overviewGrid.bootgrid('getTable');
            const row = table.getRow(interfaceId);
            if (row) row.reformat();
        }
    }

    function policyFormatter(column, row) {
        const policyId = effectivePolicy(row);
        if (row.owner === 'ha_peer') {
            const policy = policyById(policyId);
            return $('<span>')
                .addClass('text-muted')
                .text(policy ? policy.id : '{{ lang._("Unassigned") }}')[0];
        }
        const select = $('<select>')
            .addClass('form-control input-sm interface-policy-row-policy')
            .attr('data-interface', row.interface || '');
        populatePolicySelect(select, policyId, true, false);
        select.on('click', function(event) { event.stopPropagation(); });
        select.on('change', function(event) {
            event.stopPropagation();
            stageAssignment(row.interface, row.policy_id || '', $(this).val());
        });
        return $('<div>')
            .addClass('interface-policy-select-wrap')
            .append(select)[0];
    }

    function syncFormatter(column, row) {
        return behaviorElement(effectivePolicy(row));
    }

    function ownerFormatter(column, row) {
        if (row.owner === 'ha_peer') {
            return $('<span>').addClass('text-muted').text('{{ lang._("HA peer") }}')[0];
        }
        if (row.owner === 'unassigned') {
            return $('<span>').addClass('label label-warning').text('{{ lang._("Unassigned") }}')[0];
        }
        return '{{ lang._("Local") }}';
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
        overviewGrid = $('#grid-interface-policy-overview').UIBootgrid({
            search: apiBase + '/searchOverview',
            options: {
                responsive: true,
                disableScroll: true,
                rowCount: [20, 50, 100, -1],
                requestHandler: function(request) {
                    const policyFilter = $('#interface-policy-filter').val();
                    if (policyFilter && policyFilter !== '__all') {
                        request.policy_id = policyFilter;
                    }
                    return request;
                },
                selection: true,
                multiSelect: true,
                formatters: {
                    policy: policyFormatter,
                    sync: syncFormatter,
                    owner: ownerFormatter
                }
            },
            tabulatorOptions: {
                selectableRowsCheck: function(row) {
                    return row.getData().owner !== 'ha_peer';
                },
                rowFormatter: function(row) {
                    const element = $(row.getElement());
                    element.toggleClass(
                        'interface-policy-pending-row',
                        Object.prototype.hasOwnProperty.call(pendingAssignments, row.getData().interface)
                    );
                    if (row.getData().owner === 'ha_peer') {
                        element.addClass('interface-policy-peer-row');
                    }
                }
            }
        });

        $('#interface-policy-filter-container').detach()
            .insertBefore('#grid-interface-policy-overview-header .search')
            .show();
        $('#interface-policy-filter').selectpicker('refresh');
        $('#interface-policy-bulk-policy').selectpicker('refresh');
        $('#grid-interface-policy-overview')
            .on('selected.rs.jquery.bootgrid deselected.rs.jquery.bootgrid loaded.rs.jquery.bootgrid', updateBulkState);
        $('#interface-policy-bulk-policy').on('changed.bs.select change', updateBulkState);
        updateBulkState();
    }

    function refreshOverview() {
        ajaxGet(apiBase + '/overview', {}, function(data) {
            const status = $('#interface-policy-ha-status');
            const warning = $('#interface-policy-warning');

            if (!data || data.status !== 'ok') {
                status.removeClass('label-success label-default').addClass('label-danger').text('Unavailable');
                warning.removeClass('alert-warning alert-info').addClass('alert-danger')
                    .text((data && data.message) ? data.message : '{{ lang._("Unable to read interface policy state.") }}').show();
                return;
            }

            status.removeClass('label-danger label-default')
                .addClass(data.ha_service_enabled ? 'label-success' : 'label-default')
                .text(data.ha_service_enabled ? 'Enabled' : 'Disabled');

            currentPolicies = data.policies || [];
            populatePolicyFilter();
            const bulkPolicy = $('#interface-policy-bulk-policy');
            const previousBulkPolicy = bulkPolicy.val();
            populatePolicySelect(bulkPolicy, previousBulkPolicy, true, true);
            if (bulkPolicy.hasClass('selectpicker')) {
                bulkPolicy.selectpicker('refresh');
            }

            if (data.unassigned > 0) {
                warning.removeClass('alert-info alert-danger').addClass('alert-warning')
                    .text(data.unassigned + ' {{ lang._("configured interface(s) have no policy assignment. HA interface synchronization is fail-closed until every local interface is assigned.") }}')
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

    $('#grid-interface-sync-policies').UIBootgrid({
        search: apiBase + '/searchPolicy',
        get: apiBase + '/getPolicy/',
        set: apiBase + '/setPolicy/',
        add: apiBase + '/addPolicy',
        del: apiBase + '/delPolicy/'
    });

    $(document).on('changed.bs.select', '#interface-policy-filter', function() {
        if (overviewGrid) {
            overviewGrid.bootgrid('reload');
        }
    });
    $(document).on('click', '#btn-interface-policy-refresh', function() {
        if (!Object.keys(pendingAssignments).length) {
            refreshOverview();
            return;
        }
        stdDialogConfirm(
            '{{ lang._("Discard unsaved changes?") }}',
            '{{ lang._("Refreshing will discard the interface policy changes that have not been saved yet.") }}',
            '{{ lang._("Discard") }}',
            '{{ lang._("Cancel") }}',
            function() {
                pendingAssignments = {};
                updatePendingState();
                refreshOverview();
            }
        );
    });
    $(document).on('click', '#btn-interface-policy-bulk-apply', function() {
        const policyId = $('#interface-policy-bulk-policy').val();
        const selected = overviewGrid ? overviewGrid.bootgrid('getTable').getSelectedData() : [];
        if (!selected.length || !policyId) {
            assignmentFailed({message: '{{ lang._("Select at least one interface and a policy.") }}'});
            return;
        }
        selected.forEach(function(row) {
            stageAssignment(row.interface, row.policy_id || '', policyId);
        });
        updateBulkState();
    });
    $(document).on('click', '#btn-interface-policy-save-changes', savePendingAssignments);
    $(document).on('settings-changed', function() {
        pendingAssignments = {};
        updatePendingState();
        refreshOverview();
    });
    refreshOverview();
});
</script>

<div class="interface-policy-statusbar">
    <strong>{{ lang._('HA synchronization services') }}</strong>
    <span>{{ lang._('Interfaces / VLANs') }}</span>
    <span id="interface-policy-ha-status" class="label label-default">Unknown</span>
    <span>{{ lang._('HAProxy Objects') }}</span>
    <span id="haproxy-policy-ha-status" class="label label-default">Unknown</span>
</div>

<ul class="nav nav-tabs" data-tabs="tabs">
    <li class="active"><a data-toggle="tab" href="#interface-policy-overview-tab">{{ lang._('Interface Overview') }}</a></li>
    <li><a data-toggle="tab" href="#interface-policy-haproxy-tab">{{ lang._('HAProxy Objects') }}</a></li>
    <li><a data-toggle="tab" href="#interface-policy-policies-tab">{{ lang._('Policies') }}</a></li>
</ul>

<style>
.interface-policy-select-wrap {
    display: flex;
    align-items: center;
    width: 100%;
    min-height: 36px;
    padding: 2px 0;
    box-sizing: border-box;
}
.interface-policy-row-policy {
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
#grid-interface-policy-overview .tabulator-row .tabulator-cell[tabulator-field="policy_id"] {
    padding-top: 2px;
    padding-bottom: 2px;
    overflow: visible !important;
}
.interface-policy-pending-row { background-color: #fcf8e3 !important; }
.interface-policy-peer-row { opacity: 0.72; }
#interface-policy-filter-container {
    float: none !important;
    flex: 1 1 180px;
    min-width: 220px;
    max-width: 380px;
}
#interface-policy-filter-container .bootstrap-select {
    width: 100% !important;
}
#interface-policy-bulk-footer {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-left: 10px;
    vertical-align: middle;
}
#interface-policy-bulk-footer .bootstrap-select {
    width: 330px !important;
    min-width: 330px;
}
#interface-policy-bulk-footer .bootstrap-select > .dropdown-toggle,
.interface-policy-row-policy {
    overflow: visible;
    text-overflow: clip;
}
#interface-policy-selected-count,
#interface-policy-pending-count { color: #8a6d3b; white-space: nowrap; }
.interface-policy-statusbar {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 10px;
    min-height: 24px;
}
.interface-policy-help { margin-top: 12px; color: #777; }
@media (max-width: 1024px) {
    #interface-policy-filter-container {
        flex: 1 1 100%;
        max-width: 100%;
    }
    #interface-policy-bulk-footer {
        width: 100%;
        margin: 8px 0 0 0;
        flex-wrap: wrap;
    }
    #interface-policy-bulk-footer .bootstrap-select {
        width: 100% !important;
        min-width: 220px;
        max-width: 100%;
    }
}
</style>

<div class="tab-content content-box">
    <div id="interface-policy-overview-tab" class="tab-pane fade in active">
        <div class="hidden">
            <div id="interface-policy-filter-container" class="btn-group">
                <select id="interface-policy-filter"
                        class="selectpicker"
                        data-live-search="true"
                        data-size="20"
                        data-container="body"
                        data-width="100%"
                        title="{{ lang._('All policies') }}">
                </select>
            </div>
        </div>

        <table id="grid-interface-policy-overview" class="table table-condensed table-hover table-striped" style="visibility: hidden">
            <thead><tr>
                <th data-column-id="uuid" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                <th data-column-id="interface" data-type="string">{{ lang._('Interface') }}</th>
                <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                <th data-column-id="device" data-type="string">{{ lang._('Device') }}</th>
                <th data-column-id="vlan" data-type="string" data-width="90">{{ lang._('VLAN') }}</th>
                <th data-column-id="policy_id" data-type="string" data-formatter="policy" data-width="150">{{ lang._('HA Policy') }}</th>
                <th data-column-id="synchronize" data-type="string" data-formatter="sync" data-width="120">{{ lang._('Sync') }}</th>
                <th data-column-id="owner" data-type="string" data-formatter="owner" data-width="120">{{ lang._('Managed By') }}</th>
            </tr></thead>
            <tbody></tbody>
            <tfoot><tr>
                <td></td>
                <td>
                    <div id="interface-policy-bulk-footer">
                        <span id="interface-policy-selected-count" style="display:none;"></span>
                        <select id="interface-policy-bulk-policy"
                                class="selectpicker"
                                data-live-search="true"
                                data-size="20"
                                data-width="330px"
                                data-container="body"
                                title="{{ lang._('Set HA policy') }}"
                                disabled>
                        </select>
                        <button id="btn-interface-policy-bulk-apply"
                                type="button"
                                class="btn btn-xs btn-default"
                                data-toggle="tooltip"
                                data-placement="top"
                                title="{{ lang._('Set the selected HA policy on checked interfaces. Changes are staged until Save changes is pressed.') }}"
                                disabled>
                            <i class="fa fa-fw fa-tag"></i>
                            {{ lang._('Set policy') }}
                        </button>
                    </div>
                </td>
            </tr></tfoot>
        </table>

        <section id="interface-policy-overview-actions" class="grid-bottom-reserve __mt">
            <div class="alert content-box" style="display: flex; align-items: center; gap: 8px; margin-bottom: 0;">
                <button id="btn-interface-policy-save-changes" type="button" class="btn btn-primary __mr" disabled>
                    <i class="fa fa-fw fa-save"></i>
                    {{ lang._('Save changes') }}
                </button>
                <button id="btn-interface-policy-refresh" type="button" class="btn btn-default __mr">
                    <i class="fa fa-fw fa-refresh"></i>
                    {{ lang._('Refresh') }}
                </button>
                <div id="interface-policy-pending-count" style="display:none;"></div>
            </div>
        </section>

        <div class="interface-policy-help">
            <p class="help-block">
                {{ lang._('Interface policy is the explicit source of truth for VLAN/interface HA behavior. Interface names and creators do not select synchronization. The standard High Availability page separately enables the Policy-managed Interfaces / VLANs synchronization service.') }}
            </p>
            <div id="interface-policy-warning" class="alert alert-warning" style="display:none;"></div>
        </div>
    </div>

    {{ partial('OPNsense/ApiExtensions/haproxy_policy') }}

    <div id="interface-policy-policies-tab" class="tab-pane fade">
        <table id="grid-interface-sync-policies" class="table table-condensed table-hover table-striped table-responsive" data-editDialog="DialogInterfaceSyncPolicy">
            <thead><tr>
                <th data-column-id="id" data-type="string">{{ lang._('Policy ID') }}</th>
                <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                <th data-column-id="synchronize" data-type="string" data-formatter="boolean">{{ lang._('Synchronize') }}</th>
                <th data-column-id="commands" data-width="100" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
                <th data-column-id="uuid" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
            </tr></thead>
            <tbody></tbody>
            <tfoot><tr><td></td><td><button data-action="add" type="button" class="btn btn-xs btn-default"><span class="fa fa-plus"></span></button></td></tr></tfoot>
        </table>
    </div>

</div>

{{ partial('layout_partials/base_dialog', ['fields': policyForm, 'id': 'DialogInterfaceSyncPolicy', 'label': lang._('Interface Sync Policy')]) }}
