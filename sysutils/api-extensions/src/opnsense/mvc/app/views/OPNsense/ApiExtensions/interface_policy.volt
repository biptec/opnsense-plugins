<script>
$(document).ready(function() {
    $('#grid-interface-sync-policies').UIBootgrid({
        search: '/api/api_extensions/interface_policy/searchPolicy',
        get: '/api/api_extensions/interface_policy/getPolicy/',
        set: '/api/api_extensions/interface_policy/setPolicy/',
        add: '/api/api_extensions/interface_policy/addPolicy',
        del: '/api/api_extensions/interface_policy/delPolicy/'
    });
});
</script>

<div class="content-box">
    <table id="grid-interface-sync-policies"
           class="table table-condensed table-hover table-striped table-responsive"
           data-editDialog="DialogInterfaceSyncPolicy">
        <thead><tr>
            <th data-column-id="id" data-type="string">{{ lang._('Policy ID') }}</th>
            <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
            <th data-column-id="synchronize" data-type="string" data-formatter="boolean">{{ lang._('Synchronize') }}</th>
            <th data-column-id="commands" data-width="100" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
            <th data-column-id="uuid" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
        </tr></thead>
        <tbody></tbody>
        <tfoot><tr>
            <td></td>
            <td>
                <button data-action="add" type="button" class="btn btn-xs btn-default">
                    <span class="fa fa-plus"></span>
                </button>
            </td>
        </tr></tfoot>
    </table>

    <p class="help-block">
        {{ lang._('Policies define whether objects assigned to them are synchronized to the HA peer. Assign policies from the native Interfaces and HAProxy object editors.') }}
    </p>
</div>

{{ partial('layout_partials/base_dialog', ['fields': policyForm, 'id': 'DialogInterfaceSyncPolicy', 'label': lang._('Policy')]) }}
