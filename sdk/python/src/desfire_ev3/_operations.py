"""Generated from split C headers; do not hand-edit."""

from typing import Any, Callable, cast, Union

Binary = Union[bytes, bytearray, memoryview]

# Each tuple contains (parameter name, ABI marshal kind).
FUNCTIONS: dict[str, tuple[tuple[tuple[str, str], ...], str]] = {
    'df_get_version': (
        (('timeout_ms', 'u32'),),
        'bytes',
    ),
    'df_free_memory': (
        (('timeout_ms', 'u32'),),
        'u32',
    ),
    'df_select_application': (
        (('aid', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_file_ids': (
        (('timeout_ms', 'u32'),),
        'bytes',
    ),
    'df_authenticate_standard_aes': (
        (('key_number', 'u32'), ('key', 'bytes'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_authenticate_ev2_first_aes': (
        (('key_number', 'u32'), ('key', 'bytes'), ('timeout_ms', 'u32')),
        'authentication_info',
    ),
    'df_authenticate_ev2_first_aes_with_capabilities': (
        (('key_number', 'u32'), ('key', 'bytes'), ('pcd_capabilities', 'bytes'),
         ('timeout_ms', 'u32')),
        'authentication_info',
    ),
    'df_authenticate_ev2_non_first_aes': (
        (('key_number', 'u32'), ('key', 'bytes'), ('timeout_ms', 'u32')),
        'authentication_info',
    ),
    'df_application_ids': (
        (('timeout_ms', 'u32'),),
        'bytes',
    ),
    'df_iso_file_ids': (
        (('timeout_ms', 'u32'),),
        'bytes',
    ),
    'df_get_key_settings': (
        (('timeout_ms', 'u32'),),
        'bytes',
    ),
    'df_get_key_set_versions': (
        (('timeout_ms', 'u32'),),
        'bytes',
    ),
    'df_get_card_uid': (
        (('timeout_ms', 'u32'),),
        'bytes',
    ),
    'df_read_originality_signature': (
        (('timeout_ms', 'u32'),),
        'bytes',
    ),
    'df_abort_transaction': (
        (('timeout_ms', 'u32'),),
        'void',
    ),
    'df_format_picc': (
        (('timeout_ms', 'u32'),),
        'void',
    ),
    'df_delete_file': (
        (('file', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_get_file_settings': (
        (('file', 'u32'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_clear_record_file': (
        (('file', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_get_file_counters': (
        (('file', 'u32'), ('communication', 'u32'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_delete_application': (
        (('aid', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_change_key_settings': (
        (('settings', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_get_key_version': (
        (('number', 'u32'), ('key_set', 'i32'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_initialize_key_set': (
        (('key_set', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_roll_key_set': (
        (('key_set', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_finalize_key_set': (
        (('key_set', 'u32'), ('version', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_read_data': (
        (('file', 'u32'), ('offset', 'u32'), ('length', 'u32'), ('communication', 'u32'),
         ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_write_data': (
        (('file', 'u32'), ('offset', 'u32'), ('data', 'bytes'), ('communication', 'u32'),
         ('timeout_ms', 'u32')),
        'void',
    ),
    'df_write_record': (
        (('file', 'u32'), ('offset', 'u32'), ('data', 'bytes'), ('communication', 'u32'),
         ('timeout_ms', 'u32')),
        'void',
    ),
    'df_read_records': (
        (('file', 'u32'), ('first', 'u32'), ('count', 'u32'), ('communication', 'u32'),
         ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_update_record': (
        (('file', 'u32'), ('record', 'u32'), ('offset', 'u32'), ('data', 'bytes'),
         ('communication', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_credit': (
        (('file', 'u32'), ('amount', 'u32'), ('communication', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_debit': (
        (('file', 'u32'), ('amount', 'u32'), ('communication', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_limited_credit': (
        (('file', 'u32'), ('amount', 'u32'), ('communication', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_get_value': (
        (('file', 'u32'), ('communication', 'u32'), ('timeout_ms', 'u32')),
        'i32',
    ),
    'df_commit_transaction': (
        (('return_mac', 'u32'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_commit_reader_id': (
        (('reader_id', 'bytes'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_create_application': (
        (('aid', 'u32'), ('key_settings', 'u32'), ('key_count', 'u32'), ('iso_id', 'i32'),
         ('df_name', 'bytes'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_create_data_file': (
        (('file', 'u32'), ('length', 'u32'), ('communication', 'u32'), ('access_rights', 'u32'),
         ('iso_id', 'i32'), ('backup', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_create_value_file': (
        (('file', 'u32'), ('lower_limit', 'i32'), ('upper_limit', 'i32'), ('initial_value', 'i32'),
         ('communication', 'u32'), ('access_rights', 'u32'), ('limited_credit', 'u32'),
         ('free_get_value', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_create_record_file': (
        (('file', 'u32'), ('record_size', 'u32'), ('maximum_records', 'u32'),
         ('communication', 'u32'), ('access_rights', 'u32'), ('iso_id', 'i32'), ('cyclic', 'u32'),
         ('timeout_ms', 'u32')),
        'void',
    ),
    'df_change_file_settings': (
        (('file', 'u32'), ('communication', 'u32'), ('access_rights', 'u32'),
         ('command_communication', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_create_transaction_mac_file': (
        (('file', 'u32'), ('access_rights', 'u32'), ('key', 'bytes'), ('version', 'u32'),
         ('timeout_ms', 'u32')),
        'void',
    ),
    'df_change_aes_key': (
        (('number', 'u32'), ('new_key', 'bytes'), ('version', 'u32'), ('authenticated_key', 'u32'),
         ('old_key', 'bytes'), ('key_set', 'i32'), ('picc_master', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_iso_select_file': (
        (('identifier', 'u32'), ('selection', 'u32'), ('response', 'u32'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_iso_select_df_name': (
        (('name', 'bytes'), ('response', 'u32'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_iso_read_binary': (
        (('short_identifier', 'i32'), ('offset', 'u32'), ('length', 'u32'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_iso_update_binary': (
        (('short_identifier', 'i32'), ('offset', 'u32'), ('data', 'bytes'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_iso_read_records': (
        (('record', 'u32'), ('short_identifier', 'u32'), ('selection', 'u32'), ('length', 'u32'),
         ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_iso_append_record': (
        (('short_identifier', 'u32'), ('data', 'bytes'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_iso_get_challenge': (
        (('length', 'u32'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_iso_external_authenticate': (
        (('number', 'u32'), ('application', 'u32'), ('algorithm', 'u32'), ('data', 'bytes'),
         ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_iso_internal_authenticate': (
        (('number', 'u32'), ('application', 'u32'), ('algorithm', 'u32'), ('data', 'bytes'),
         ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_authenticate_iso_aes': (
        (('number', 'u32'), ('application', 'u32'), ('key', 'bytes'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_get_df_names': (
        (('timeout_ms', 'u32'),),
        'bytes',
    ),
    'df_reset_authentication': (
        (),
        'void',
    ),
    'df_restore_transfer': (
        (('target_file', 'u32'), ('source_file', 'u32'), ('communication', 'u32'),
         ('timeout_ms', 'u32')),
        'void',
    ),
    'df_create_delegated_application': (
        (('aid', 'u32'), ('key_settings', 'u32'), ('number_of_keys', 'u32'), ('slot', 'u32'),
         ('slot_version', 'u32'), ('quota_limit', 'u32'), ('iso_file_identifiers', 'u32'),
         ('key_settings3', 'i32'), ('iso_id', 'i32'), ('df_name', 'bytes'),
         ('encrypted_default_key', 'bytes'), ('dam_mac', 'bytes'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_get_delegated_application_info': (
        (('slot', 'u32'), ('timeout_ms', 'u32')),
        'delegated_application_info',
    ),
    'df_delete_delegated_application': (
        (('aid', 'u32'), ('dam_mac', 'bytes'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_get_card_uid_variant': (
        (('option', 'u32'), ('timeout_ms', 'u32')),
        'bytes',
    ),
    'df_set_capability_configuration': (
        (('capabilities', 'bytes'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_set_default_aes_key': (
        (('key', 'bytes'), ('key_version', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_set_ats': (
        (('ats', 'bytes'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_set_atqa': (
        (('atqa', 'u32'), ('timeout_ms', 'u32')),
        'void',
    ),
    'df_iso_update_record': (
        (('instruction', 'u32'), ('record', 'u32'), ('short_identifier', 'u32'),
         ('reference_control', 'u32'), ('data', 'bytes'), ('timeout_ms', 'u32')),
        'bytes',
    ),
}


class Operations:
    """Complete direct-key managed C operations with Python-owned results."""

    _invoke: Callable[[str, tuple[Any, ...]], Any]

    def get_version(
        self,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_get_version`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_get_version', (
            timeout_ms,
        )))

    def free_memory(
        self,
        timeout_ms: int = 5000,
    ) -> int:
        """Invoke ``df_free_memory`` once and preserve its result and delivery evidence."""
        return cast(int, self._invoke('df_free_memory', (
            timeout_ms,
        )))

    def select_application(
        self,
        aid: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_select_application`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_select_application', (
            aid,
            timeout_ms,
        )))

    def file_ids(
        self,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_file_ids`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_file_ids', (
            timeout_ms,
        )))

    def application_ids(
        self,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_application_ids`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_application_ids', (
            timeout_ms,
        )))

    def iso_file_ids(
        self,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_file_ids`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_file_ids', (
            timeout_ms,
        )))

    def get_key_settings(
        self,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_get_key_settings`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_get_key_settings', (
            timeout_ms,
        )))

    def get_key_set_versions(
        self,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_get_key_set_versions`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_get_key_set_versions', (
            timeout_ms,
        )))

    def get_card_uid(
        self,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_get_card_uid`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_get_card_uid', (
            timeout_ms,
        )))

    def read_originality_signature(
        self,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_read_originality_signature`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_read_originality_signature', (
            timeout_ms,
        )))

    def abort_transaction(
        self,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_abort_transaction`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_abort_transaction', (
            timeout_ms,
        )))

    def format_picc(
        self,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_format_picc`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_format_picc', (
            timeout_ms,
        )))

    def delete_file(
        self,
        file: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_delete_file`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_delete_file', (
            file,
            timeout_ms,
        )))

    def get_file_settings(
        self,
        file: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_get_file_settings`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_get_file_settings', (
            file,
            timeout_ms,
        )))

    def clear_record_file(
        self,
        file: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_clear_record_file`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_clear_record_file', (
            file,
            timeout_ms,
        )))

    def get_file_counters(
        self,
        file: int,
        communication: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_get_file_counters`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_get_file_counters', (
            file,
            communication,
            timeout_ms,
        )))

    def delete_application(
        self,
        aid: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_delete_application`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_delete_application', (
            aid,
            timeout_ms,
        )))

    def change_key_settings(
        self,
        settings: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_change_key_settings`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_change_key_settings', (
            settings,
            timeout_ms,
        )))

    def get_key_version(
        self,
        number: int,
        key_set: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_get_key_version`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_get_key_version', (
            number,
            key_set,
            timeout_ms,
        )))

    def initialize_key_set(
        self,
        key_set: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_initialize_key_set`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_initialize_key_set', (
            key_set,
            timeout_ms,
        )))

    def roll_key_set(
        self,
        key_set: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_roll_key_set`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_roll_key_set', (
            key_set,
            timeout_ms,
        )))

    def finalize_key_set(
        self,
        key_set: int,
        version: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_finalize_key_set`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_finalize_key_set', (
            key_set,
            version,
            timeout_ms,
        )))

    def read_data(
        self,
        file: int,
        offset: int,
        length: int,
        communication: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_read_data`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_read_data', (
            file,
            offset,
            length,
            communication,
            timeout_ms,
        )))

    def write_data(
        self,
        file: int,
        offset: int,
        data: Binary,
        communication: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_write_data`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_write_data', (
            file,
            offset,
            data,
            communication,
            timeout_ms,
        )))

    def write_record(
        self,
        file: int,
        offset: int,
        data: Binary,
        communication: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_write_record`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_write_record', (
            file,
            offset,
            data,
            communication,
            timeout_ms,
        )))

    def read_records(
        self,
        file: int,
        first: int,
        count: int,
        communication: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_read_records`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_read_records', (
            file,
            first,
            count,
            communication,
            timeout_ms,
        )))

    def update_record(
        self,
        file: int,
        record: int,
        offset: int,
        data: Binary,
        communication: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_update_record`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_update_record', (
            file,
            record,
            offset,
            data,
            communication,
            timeout_ms,
        )))

    def credit(
        self,
        file: int,
        amount: int,
        communication: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_credit`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_credit', (
            file,
            amount,
            communication,
            timeout_ms,
        )))

    def debit(
        self,
        file: int,
        amount: int,
        communication: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_debit`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_debit', (
            file,
            amount,
            communication,
            timeout_ms,
        )))

    def limited_credit(
        self,
        file: int,
        amount: int,
        communication: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_limited_credit`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_limited_credit', (
            file,
            amount,
            communication,
            timeout_ms,
        )))

    def get_value(
        self,
        file: int,
        communication: int,
        timeout_ms: int = 5000,
    ) -> int:
        """Invoke ``df_get_value`` once and preserve its result and delivery evidence."""
        return cast(int, self._invoke('df_get_value', (
            file,
            communication,
            timeout_ms,
        )))

    def commit_transaction(
        self,
        return_mac: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_commit_transaction`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_commit_transaction', (
            return_mac,
            timeout_ms,
        )))

    def commit_reader_id(
        self,
        reader_id: Binary,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_commit_reader_id`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_commit_reader_id', (
            reader_id,
            timeout_ms,
        )))

    def create_application(
        self,
        aid: int,
        key_settings: int,
        key_count: int,
        iso_id: int,
        df_name: Binary,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_create_application`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_create_application', (
            aid,
            key_settings,
            key_count,
            iso_id,
            df_name,
            timeout_ms,
        )))

    def create_data_file(
        self,
        file: int,
        length: int,
        communication: int,
        access_rights: int,
        iso_id: int,
        backup: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_create_data_file`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_create_data_file', (
            file,
            length,
            communication,
            access_rights,
            iso_id,
            backup,
            timeout_ms,
        )))

    def create_value_file(
        self,
        file: int,
        lower_limit: int,
        upper_limit: int,
        initial_value: int,
        communication: int,
        access_rights: int,
        limited_credit: int,
        free_get_value: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_create_value_file`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_create_value_file', (
            file,
            lower_limit,
            upper_limit,
            initial_value,
            communication,
            access_rights,
            limited_credit,
            free_get_value,
            timeout_ms,
        )))

    def create_record_file(
        self,
        file: int,
        record_size: int,
        maximum_records: int,
        communication: int,
        access_rights: int,
        iso_id: int,
        cyclic: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_create_record_file`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_create_record_file', (
            file,
            record_size,
            maximum_records,
            communication,
            access_rights,
            iso_id,
            cyclic,
            timeout_ms,
        )))

    def change_file_settings(
        self,
        file: int,
        communication: int,
        access_rights: int,
        command_communication: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_change_file_settings`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_change_file_settings', (
            file,
            communication,
            access_rights,
            command_communication,
            timeout_ms,
        )))

    def create_transaction_mac_file(
        self,
        file: int,
        access_rights: int,
        key: Binary,
        version: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_create_transaction_mac_file`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_create_transaction_mac_file', (
            file,
            access_rights,
            key,
            version,
            timeout_ms,
        )))

    def change_aes_key(
        self,
        number: int,
        new_key: Binary,
        version: int,
        authenticated_key: int,
        old_key: Binary,
        key_set: int,
        picc_master: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_change_aes_key`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_change_aes_key', (
            number,
            new_key,
            version,
            authenticated_key,
            old_key,
            key_set,
            picc_master,
            timeout_ms,
        )))

    def iso_select_file(
        self,
        identifier: int,
        selection: int,
        response: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_select_file`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_select_file', (
            identifier,
            selection,
            response,
            timeout_ms,
        )))

    def iso_select_df_name(
        self,
        name: Binary,
        response: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_select_df_name`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_select_df_name', (
            name,
            response,
            timeout_ms,
        )))

    def iso_read_binary(
        self,
        short_identifier: int,
        offset: int,
        length: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_read_binary`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_read_binary', (
            short_identifier,
            offset,
            length,
            timeout_ms,
        )))

    def iso_update_binary(
        self,
        short_identifier: int,
        offset: int,
        data: Binary,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_update_binary`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_update_binary', (
            short_identifier,
            offset,
            data,
            timeout_ms,
        )))

    def iso_read_records(
        self,
        record: int,
        short_identifier: int,
        selection: int,
        length: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_read_records`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_read_records', (
            record,
            short_identifier,
            selection,
            length,
            timeout_ms,
        )))

    def iso_append_record(
        self,
        short_identifier: int,
        data: Binary,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_append_record`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_append_record', (
            short_identifier,
            data,
            timeout_ms,
        )))

    def iso_get_challenge(
        self,
        length: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_get_challenge`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_get_challenge', (
            length,
            timeout_ms,
        )))

    def iso_external_authenticate(
        self,
        number: int,
        application: int,
        algorithm: int,
        data: Binary,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_external_authenticate`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_external_authenticate', (
            number,
            application,
            algorithm,
            data,
            timeout_ms,
        )))

    def iso_internal_authenticate(
        self,
        number: int,
        application: int,
        algorithm: int,
        data: Binary,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_internal_authenticate`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_internal_authenticate', (
            number,
            application,
            algorithm,
            data,
            timeout_ms,
        )))

    def get_df_names(
        self,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_get_df_names`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_get_df_names', (
            timeout_ms,
        )))

    def reset_authentication(
        self,
    ) -> None:
        """Invoke ``df_reset_authentication`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_reset_authentication', (
        )))

    def restore_transfer(
        self,
        target_file: int,
        source_file: int,
        communication: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_restore_transfer`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_restore_transfer', (
            target_file,
            source_file,
            communication,
            timeout_ms,
        )))

    def create_delegated_application(
        self,
        aid: int,
        key_settings: int,
        number_of_keys: int,
        slot: int,
        slot_version: int,
        quota_limit: int,
        iso_file_identifiers: int,
        key_settings3: int,
        iso_id: int,
        df_name: Binary,
        encrypted_default_key: Binary,
        dam_mac: Binary,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_create_delegated_application`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_create_delegated_application', (
            aid,
            key_settings,
            number_of_keys,
            slot,
            slot_version,
            quota_limit,
            iso_file_identifiers,
            key_settings3,
            iso_id,
            df_name,
            encrypted_default_key,
            dam_mac,
            timeout_ms,
        )))

    def get_delegated_application_info(
        self,
        slot: int,
        timeout_ms: int = 5000,
    ) -> Any:
        """Invoke ``df_get_delegated_application_info`` once and preserve its result and delivery evidence."""
        return cast(Any, self._invoke('df_get_delegated_application_info', (
            slot,
            timeout_ms,
        )))

    def delete_delegated_application(
        self,
        aid: int,
        dam_mac: Binary,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_delete_delegated_application`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_delete_delegated_application', (
            aid,
            dam_mac,
            timeout_ms,
        )))

    def get_card_uid_variant(
        self,
        option: int,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_get_card_uid_variant`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_get_card_uid_variant', (
            option,
            timeout_ms,
        )))

    def set_capability_configuration(
        self,
        capabilities: Binary,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_set_capability_configuration`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_set_capability_configuration', (
            capabilities,
            timeout_ms,
        )))

    def set_default_aes_key(
        self,
        key: Binary,
        key_version: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_set_default_aes_key`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_set_default_aes_key', (
            key,
            key_version,
            timeout_ms,
        )))

    def set_ats(
        self,
        ats: Binary,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_set_ats`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_set_ats', (
            ats,
            timeout_ms,
        )))

    def set_atqa(
        self,
        atqa: int,
        timeout_ms: int = 5000,
    ) -> None:
        """Invoke ``df_set_atqa`` once and preserve its result and delivery evidence."""
        return cast(None, self._invoke('df_set_atqa', (
            atqa,
            timeout_ms,
        )))

    def iso_update_record(
        self,
        instruction: int,
        record: int,
        short_identifier: int,
        reference_control: int,
        data: Binary,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Invoke ``df_iso_update_record`` once and preserve its result and delivery evidence."""
        return cast(bytes, self._invoke('df_iso_update_record', (
            instruction,
            record,
            short_identifier,
            reference_control,
            data,
            timeout_ms,
        )))
