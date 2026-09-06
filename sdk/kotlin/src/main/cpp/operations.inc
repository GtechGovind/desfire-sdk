// Private checked C ABI dispatch for typed managed Kotlin operations.
case 0: {
    // df_reset
    require_counts(numbers.size(), 0, blobs.size(), 0);
    status = df_reset(handle, &error);
    break;
}
case 1: {
    // df_cancel
    require_counts(numbers.size(), 0, blobs.size(), 0);
    status = df_cancel(handle, &error);
    break;
}
case 2: {
    // df_notify_state_change
    require_counts(numbers.size(), 0, blobs.size(), 0);
    status = df_notify_state_change(handle, &error);
    break;
}
case 3: {
    // df_get_version
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_get_version(handle, static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 4: {
    // df_free_memory
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    uint32_t scalar_output{};
    status = df_free_memory(handle, static_cast<uint32_t>(numbers[0]), &scalar_output, &error);
    if (status == DF_OK) {
        const auto value = static_cast<uint32_t>(scalar_output);
        scalar_result = {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8U),
            static_cast<uint8_t>(value >> 16U), static_cast<uint8_t>(value >> 24U)};
    }
    break;
}
case 5: {
    // df_select_application
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_select_application(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &error);
    break;
}
case 6: {
    // df_file_ids
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_file_ids(handle, static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 7: {
    // Reserved after removing the ambiguous pre-v1 authentication operation.
    throw std::invalid_argument("removed authentication operation");
}
case 8: {
    // df_application_ids
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_application_ids(handle, static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 9: {
    // df_iso_file_ids
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_iso_file_ids(handle, static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 10: {
    // df_get_key_settings
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_get_key_settings(handle, static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 11: {
    // df_get_key_set_versions
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_get_key_set_versions(handle, static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 12: {
    // df_get_card_uid
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_get_card_uid(handle, static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 13: {
    // df_read_originality_signature
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_read_originality_signature(handle, static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 14: {
    // df_abort_transaction
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_abort_transaction(handle, static_cast<uint32_t>(numbers[0]), &error);
    break;
}
case 15: {
    // df_format_picc
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_format_picc(handle, static_cast<uint32_t>(numbers[0]), &error);
    break;
}
case 16: {
    // df_delete_file
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_delete_file(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &error);
    break;
}
case 17: {
    // df_get_file_settings
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_get_file_settings(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &output, &error);
    break;
}
case 18: {
    // df_clear_record_file
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_clear_record_file(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &error);
    break;
}
case 19: {
    // df_get_file_counters
    require_counts(numbers.size(), 3, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    status = df_get_file_counters(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), &output, &error);
    break;
}
case 20: {
    // df_delete_application
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_delete_application(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &error);
    break;
}
case 21: {
    // df_change_key_settings
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_change_key_settings(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &error);
    break;
}
case 22: {
    // df_get_key_version
    require_counts(numbers.size(), 3, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_signed(numbers[1]);
    require_unsigned(numbers[2]);
    status = df_get_key_version(handle, static_cast<uint32_t>(numbers[0]), static_cast<int32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), &output, &error);
    break;
}
case 23: {
    // df_initialize_key_set
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_initialize_key_set(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &error);
    break;
}
case 24: {
    // df_roll_key_set
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_roll_key_set(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &error);
    break;
}
case 25: {
    // df_finalize_key_set
    require_counts(numbers.size(), 3, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    status = df_finalize_key_set(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), &error);
    break;
}
case 26: {
    // df_read_data
    require_counts(numbers.size(), 5, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    require_unsigned(numbers[4]);
    status = df_read_data(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), static_cast<uint32_t>(numbers[4]), &output, &error);
    break;
}
case 27: {
    // df_write_data
    require_counts(numbers.size(), 4, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_write_data(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), &error);
    break;
}
case 28: {
    // df_write_record
    require_counts(numbers.size(), 4, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_write_record(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), &error);
    break;
}
case 29: {
    // df_read_records
    require_counts(numbers.size(), 5, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    require_unsigned(numbers[4]);
    status = df_read_records(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), static_cast<uint32_t>(numbers[4]), &output, &error);
    break;
}
case 30: {
    // df_update_record
    require_counts(numbers.size(), 5, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    require_unsigned(numbers[4]);
    status = df_update_record(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[3]), static_cast<uint32_t>(numbers[4]), &error);
    break;
}
case 31: {
    // df_credit
    require_counts(numbers.size(), 4, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_credit(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), &error);
    break;
}
case 32: {
    // df_debit
    require_counts(numbers.size(), 4, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_debit(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), &error);
    break;
}
case 33: {
    // df_limited_credit
    require_counts(numbers.size(), 4, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_limited_credit(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), &error);
    break;
}
case 34: {
    // df_get_value
    require_counts(numbers.size(), 3, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    int32_t scalar_output{};
    status = df_get_value(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), &scalar_output, &error);
    if (status == DF_OK) {
        const auto value = static_cast<uint32_t>(scalar_output);
        scalar_result = {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8U),
            static_cast<uint8_t>(value >> 16U), static_cast<uint8_t>(value >> 24U)};
    }
    break;
}
case 35: {
    // df_commit_transaction
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_commit_transaction(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &output, &error);
    break;
}
case 36: {
    // df_commit_reader_id
    require_counts(numbers.size(), 1, blobs.size(), 1);
    require_unsigned(numbers[0]);
    status = df_commit_reader_id(handle, blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 37: {
    // df_create_application
    require_counts(numbers.size(), 5, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_signed(numbers[3]);
    require_unsigned(numbers[4]);
    status = df_create_application(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<int32_t>(numbers[3]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[4]), &error);
    break;
}
case 38: {
    // df_create_data_file
    require_counts(numbers.size(), 7, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    require_signed(numbers[4]);
    require_unsigned(numbers[5]);
    require_unsigned(numbers[6]);
    status = df_create_data_file(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), static_cast<int32_t>(numbers[4]), static_cast<uint32_t>(numbers[5]), static_cast<uint32_t>(numbers[6]), &error);
    break;
}
case 39: {
    // df_create_value_file
    require_counts(numbers.size(), 9, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_signed(numbers[1]);
    require_signed(numbers[2]);
    require_signed(numbers[3]);
    require_unsigned(numbers[4]);
    require_unsigned(numbers[5]);
    require_unsigned(numbers[6]);
    require_unsigned(numbers[7]);
    require_unsigned(numbers[8]);
    status = df_create_value_file(handle, static_cast<uint32_t>(numbers[0]), static_cast<int32_t>(numbers[1]), static_cast<int32_t>(numbers[2]), static_cast<int32_t>(numbers[3]), static_cast<uint32_t>(numbers[4]), static_cast<uint32_t>(numbers[5]), static_cast<uint32_t>(numbers[6]), static_cast<uint32_t>(numbers[7]), static_cast<uint32_t>(numbers[8]), &error);
    break;
}
case 40: {
    // df_create_record_file
    require_counts(numbers.size(), 8, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    require_unsigned(numbers[4]);
    require_signed(numbers[5]);
    require_unsigned(numbers[6]);
    require_unsigned(numbers[7]);
    status = df_create_record_file(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), static_cast<uint32_t>(numbers[4]), static_cast<int32_t>(numbers[5]), static_cast<uint32_t>(numbers[6]), static_cast<uint32_t>(numbers[7]), &error);
    break;
}
case 41: {
    // df_change_file_settings
    require_counts(numbers.size(), 5, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    require_unsigned(numbers[4]);
    status = df_change_file_settings(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), static_cast<uint32_t>(numbers[4]), &error);
    break;
}
case 42: {
    // df_create_transaction_mac_file
    require_counts(numbers.size(), 4, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_create_transaction_mac_file(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), &error);
    break;
}
case 43: {
    // df_change_aes_key
    require_counts(numbers.size(), 6, blobs.size(), 2);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_signed(numbers[3]);
    require_unsigned(numbers[4]);
    require_unsigned(numbers[5]);
    status = df_change_aes_key(handle, static_cast<uint32_t>(numbers[0]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), blobs[1].data(), blobs[1].size(), static_cast<int32_t>(numbers[3]), static_cast<uint32_t>(numbers[4]), static_cast<uint32_t>(numbers[5]), &error);
    break;
}
case 44: {
    // df_iso_select_file
    require_counts(numbers.size(), 4, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_iso_select_file(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), &output, &error);
    break;
}
case 45: {
    // df_iso_select_df_name
    require_counts(numbers.size(), 2, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_iso_select_df_name(handle, blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &output, &error);
    break;
}
case 46: {
    // df_iso_read_binary
    require_counts(numbers.size(), 4, blobs.size(), 0);
    require_signed(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_iso_read_binary(handle, static_cast<int32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), &output, &error);
    break;
}
case 47: {
    // df_iso_update_binary
    require_counts(numbers.size(), 3, blobs.size(), 1);
    require_signed(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    status = df_iso_update_binary(handle, static_cast<int32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[2]), &output, &error);
    break;
}
case 48: {
    // df_iso_read_records
    require_counts(numbers.size(), 5, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    require_unsigned(numbers[4]);
    status = df_iso_read_records(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]), static_cast<uint32_t>(numbers[4]), &output, &error);
    break;
}
case 49: {
    // df_iso_append_record
    require_counts(numbers.size(), 2, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_iso_append_record(handle, static_cast<uint32_t>(numbers[0]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[1]), &output, &error);
    break;
}
case 50: {
    // df_iso_get_challenge
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_iso_get_challenge(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), &output, &error);
    break;
}
case 51: {
    // df_iso_external_authenticate
    require_counts(numbers.size(), 4, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_iso_external_authenticate(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[3]), &output, &error);
    break;
}
case 52: {
    // df_iso_internal_authenticate
    require_counts(numbers.size(), 4, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    require_unsigned(numbers[3]);
    status = df_iso_internal_authenticate(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), static_cast<uint32_t>(numbers[2]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[3]), &output, &error);
    break;
}
case 53: {
    // df_authenticate_iso_aes
    require_counts(numbers.size(), 3, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    require_unsigned(numbers[2]);
    status = df_authenticate_iso_aes(handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]), blobs[0].data(), blobs[0].size(), static_cast<uint32_t>(numbers[2]), &error);
    break;
}
case 54: {
    // df_get_df_names
    require_counts(numbers.size(), 1, blobs.size(), 0);
    require_unsigned(numbers[0]);
    status = df_get_df_names(handle, static_cast<uint32_t>(numbers[0]), &output, &error);
    break;
}
case 55: {
    // df_reset_authentication
    require_counts(numbers.size(), 0, blobs.size(), 0);
    status = df_reset_authentication(handle, &error);
    break;
}
case 56: {
    // df_restore_transfer
    require_counts(numbers.size(), 4, blobs.size(), 0);
    for (std::size_t index = 0; index < numbers.size(); ++index) {
        require_unsigned(numbers[index]);
    }
    status = df_restore_transfer(handle, static_cast<uint32_t>(numbers[0]),
                                 static_cast<uint32_t>(numbers[1]),
                                 static_cast<uint32_t>(numbers[2]),
                                 static_cast<uint32_t>(numbers[3]), &error);
    break;
}
case 57: {
    // df_create_delegated_application
    require_counts(numbers.size(), 10, blobs.size(), 3);
    for (std::size_t index : {0U, 1U, 2U, 3U, 4U, 5U, 6U, 9U}) {
        require_unsigned(numbers[index]);
    }
    require_signed(numbers[7]);
    require_signed(numbers[8]);
    status = df_create_delegated_application(
        handle, static_cast<uint32_t>(numbers[0]), static_cast<uint32_t>(numbers[1]),
        static_cast<uint32_t>(numbers[2]), static_cast<uint32_t>(numbers[3]),
        static_cast<uint32_t>(numbers[4]), static_cast<uint32_t>(numbers[5]),
        static_cast<uint32_t>(numbers[6]), static_cast<int32_t>(numbers[7]),
        static_cast<int32_t>(numbers[8]), blobs[0].data(), blobs[0].size(),
        blobs[1].data(), blobs[1].size(), blobs[2].data(), blobs[2].size(),
        static_cast<uint32_t>(numbers[9]), &error);
    break;
}
case 58: {
    // df_get_delegated_application_info
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    df_delegated_application_info_v1 information{};
    information.struct_size = sizeof(information);
    information.abi_version = DF_ABI_VERSION;
    status = df_get_delegated_application_info(handle, static_cast<uint32_t>(numbers[0]),
                                                static_cast<uint32_t>(numbers[1]),
                                                &information, &error);
    if (status == DF_OK) {
        scalar_result.reserve(16U);
        append_u32(scalar_result, information.slot_version);
        append_u32(scalar_result, information.quota_limit);
        append_u32(scalar_result, information.free_blocks);
        append_u32(scalar_result, information.application_id);
    }
    break;
}
case 59: {
    // df_delete_delegated_application
    require_counts(numbers.size(), 2, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_delete_delegated_application(handle, static_cast<uint32_t>(numbers[0]),
                                              blobs[0].data(), blobs[0].size(),
                                              static_cast<uint32_t>(numbers[1]), &error);
    break;
}
case 60: {
    // df_get_card_uid_variant
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_get_card_uid_variant(handle, static_cast<uint32_t>(numbers[0]),
                                     static_cast<uint32_t>(numbers[1]), &output, &error);
    break;
}
case 61: {
    // df_set_picc_configuration
    require_counts(numbers.size(), 8, blobs.size(), 0);
    for (const auto value : numbers) {
        require_unsigned(value);
    }
    df_picc_configuration_v1 configuration{};
    configuration.struct_size = sizeof(configuration);
    configuration.abi_version = DF_ABI_VERSION;
    configuration.disable_format = static_cast<uint32_t>(numbers[0]);
    configuration.random_identifier = static_cast<uint32_t>(numbers[1]);
    configuration.proximity_check_mandatory = static_cast<uint32_t>(numbers[2]);
    configuration.virtual_card_authentication_mandatory = static_cast<uint32_t>(numbers[3]);
    configuration.error_code_binding = static_cast<uint32_t>(numbers[4]);
    configuration.random_identifier_configuration = static_cast<uint32_t>(numbers[5]);
    configuration.four_byte_nuid_configuration = static_cast<uint32_t>(numbers[6]);
    status = df_set_picc_configuration(handle, &configuration,
                                       static_cast<uint32_t>(numbers[7]), &error);
    break;
}
case 62: {
    // df_set_capability_configuration
    require_counts(numbers.size(), 1, blobs.size(), 1);
    require_unsigned(numbers[0]);
    status = df_set_capability_configuration(handle, blobs[0].data(), blobs[0].size(),
                                              static_cast<uint32_t>(numbers[0]), &error);
    break;
}
case 63: {
    // df_set_ats
    require_counts(numbers.size(), 1, blobs.size(), 1);
    require_unsigned(numbers[0]);
    status = df_set_ats(handle, blobs[0].data(), blobs[0].size(),
                        static_cast<uint32_t>(numbers[0]), &error);
    break;
}
case 64: {
    // df_set_atqa
    require_counts(numbers.size(), 2, blobs.size(), 0);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    status = df_set_atqa(handle, static_cast<uint32_t>(numbers[0]),
                         static_cast<uint32_t>(numbers[1]), &error);
    break;
}
case 65: {
    // df_iso_update_record
    require_counts(numbers.size(), 5, blobs.size(), 1);
    for (const auto value : numbers) {
        require_unsigned(value);
    }
    status = df_iso_update_record(handle, static_cast<uint32_t>(numbers[0]),
                                  static_cast<uint32_t>(numbers[1]),
                                  static_cast<uint32_t>(numbers[2]),
                                  static_cast<uint32_t>(numbers[3]), blobs[0].data(),
                                  blobs[0].size(), static_cast<uint32_t>(numbers[4]),
                                  &output, &error);
    break;
}
case 66: {
    // df_execute_transaction
    require_counts(numbers.size(), 2, blobs.size(), 1);
    require_unsigned(numbers[0]);
    require_unsigned(numbers[1]);
    auto transaction = decode_transaction_plan(blobs[0]);
    status = df_execute_transaction(handle, transaction.operations.data(),
                                    transaction.operations.size(),
                                    static_cast<uint32_t>(numbers[0]),
                                    static_cast<uint32_t>(numbers[1]), &output, &error);
    break;
}
