/** @file dispatch.inc Generated C ABI calls; no card protocol encoding. */
napi_value dispatch_managed(napi_env env, Context& context, const std::string& operation,
                            napi_value arguments) {
    df_error error{};
    if (operation == "df_get_version") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        df_buffer* out = nullptr;
        const auto status = df_get_version(context.card, timeout_ms, &out, &error);
        BufferOwner owned_out(out);
        check_native(env, status, error);
        return buffer_result(env, owned_out.get());
    }
    if (operation == "df_free_memory") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        std::uint32_t out{};
        const auto status = df_free_memory(context.card, timeout_ms, &out, &error);
        check_native(env, status, error);
        return number_result(env, out);
    }
    if (operation == "df_select_application") {
        require_count(env, arguments, 2);
        auto aid = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_select_application(context.card, aid, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_file_ids") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        df_buffer* out = nullptr;
        const auto status = df_file_ids(context.card, timeout_ms, &out, &error);
        BufferOwner owned_out(out);
        check_native(env, status, error);
        return buffer_result(env, owned_out.get());
    }
    if (operation == "df_authenticate_standard_aes") {
        require_count(env, arguments, 3);
        auto key_number = u32(env, argument(env, arguments, 0));
        auto key = binary(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        const auto status = df_authenticate_standard_aes(context.card, key_number, key.data, key.size, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_application_ids") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        df_buffer* output = nullptr;
        const auto status = df_application_ids(context.card, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_iso_file_ids") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        df_buffer* output = nullptr;
        const auto status = df_iso_file_ids(context.card, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_get_key_settings") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        df_buffer* output = nullptr;
        const auto status = df_get_key_settings(context.card, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_get_key_set_versions") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        df_buffer* output = nullptr;
        const auto status = df_get_key_set_versions(context.card, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_get_card_uid") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        df_buffer* output = nullptr;
        const auto status = df_get_card_uid(context.card, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_read_originality_signature") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        df_buffer* output = nullptr;
        const auto status = df_read_originality_signature(context.card, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_abort_transaction") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        const auto status = df_abort_transaction(context.card, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_format_picc") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        const auto status = df_format_picc(context.card, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_delete_file") {
        require_count(env, arguments, 2);
        auto file = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_delete_file(context.card, file, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_get_file_settings") {
        require_count(env, arguments, 2);
        auto file = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        df_buffer* output = nullptr;
        const auto status = df_get_file_settings(context.card, file, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_clear_record_file") {
        require_count(env, arguments, 2);
        auto file = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_clear_record_file(context.card, file, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_get_file_counters") {
        require_count(env, arguments, 3);
        auto file = u32(env, argument(env, arguments, 0));
        auto communication = u32(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_get_file_counters(context.card, file, communication, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_delete_application") {
        require_count(env, arguments, 2);
        auto aid = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_delete_application(context.card, aid, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_change_key_settings") {
        require_count(env, arguments, 2);
        auto settings = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_change_key_settings(context.card, settings, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_get_key_version") {
        require_count(env, arguments, 3);
        auto number = u32(env, argument(env, arguments, 0));
        auto key_set = i32(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_get_key_version(context.card, number, key_set, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_initialize_key_set") {
        require_count(env, arguments, 2);
        auto key_set = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_initialize_key_set(context.card, key_set, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_roll_key_set") {
        require_count(env, arguments, 2);
        auto key_set = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_roll_key_set(context.card, key_set, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_finalize_key_set") {
        require_count(env, arguments, 3);
        auto key_set = u32(env, argument(env, arguments, 0));
        auto version = u32(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        const auto status = df_finalize_key_set(context.card, key_set, version, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_read_data") {
        require_count(env, arguments, 5);
        auto file = u32(env, argument(env, arguments, 0));
        auto offset = u32(env, argument(env, arguments, 1));
        auto length = u32(env, argument(env, arguments, 2));
        auto communication = u32(env, argument(env, arguments, 3));
        auto timeout_ms = u32(env, argument(env, arguments, 4));
        df_buffer* output = nullptr;
        const auto status = df_read_data(context.card, file, offset, length, communication, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_write_data") {
        require_count(env, arguments, 5);
        auto file = u32(env, argument(env, arguments, 0));
        auto offset = u32(env, argument(env, arguments, 1));
        auto data = binary(env, argument(env, arguments, 2));
        auto communication = u32(env, argument(env, arguments, 3));
        auto timeout_ms = u32(env, argument(env, arguments, 4));
        const auto status = df_write_data(context.card, file, offset, data.data, data.size, communication, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_write_record") {
        require_count(env, arguments, 5);
        auto file = u32(env, argument(env, arguments, 0));
        auto offset = u32(env, argument(env, arguments, 1));
        auto data = binary(env, argument(env, arguments, 2));
        auto communication = u32(env, argument(env, arguments, 3));
        auto timeout_ms = u32(env, argument(env, arguments, 4));
        const auto status = df_write_record(context.card, file, offset, data.data, data.size, communication, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_read_records") {
        require_count(env, arguments, 5);
        auto file = u32(env, argument(env, arguments, 0));
        auto first = u32(env, argument(env, arguments, 1));
        auto count = u32(env, argument(env, arguments, 2));
        auto communication = u32(env, argument(env, arguments, 3));
        auto timeout_ms = u32(env, argument(env, arguments, 4));
        df_buffer* output = nullptr;
        const auto status = df_read_records(context.card, file, first, count, communication, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_update_record") {
        require_count(env, arguments, 6);
        auto file = u32(env, argument(env, arguments, 0));
        auto record = u32(env, argument(env, arguments, 1));
        auto offset = u32(env, argument(env, arguments, 2));
        auto data = binary(env, argument(env, arguments, 3));
        auto communication = u32(env, argument(env, arguments, 4));
        auto timeout_ms = u32(env, argument(env, arguments, 5));
        const auto status = df_update_record(context.card, file, record, offset, data.data, data.size, communication, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_credit") {
        require_count(env, arguments, 4);
        auto file = u32(env, argument(env, arguments, 0));
        auto amount = u32(env, argument(env, arguments, 1));
        auto communication = u32(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        const auto status = df_credit(context.card, file, amount, communication, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_debit") {
        require_count(env, arguments, 4);
        auto file = u32(env, argument(env, arguments, 0));
        auto amount = u32(env, argument(env, arguments, 1));
        auto communication = u32(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        const auto status = df_debit(context.card, file, amount, communication, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_limited_credit") {
        require_count(env, arguments, 4);
        auto file = u32(env, argument(env, arguments, 0));
        auto amount = u32(env, argument(env, arguments, 1));
        auto communication = u32(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        const auto status = df_limited_credit(context.card, file, amount, communication, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_get_value") {
        require_count(env, arguments, 3);
        auto file = u32(env, argument(env, arguments, 0));
        auto communication = u32(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        std::int32_t output{};
        const auto status = df_get_value(context.card, file, communication, timeout_ms, &output, &error);
        check_native(env, status, error);
        return number_result(env, output);
    }
    if (operation == "df_commit_transaction") {
        require_count(env, arguments, 2);
        auto return_mac = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        df_buffer* output = nullptr;
        const auto status = df_commit_transaction(context.card, return_mac, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_commit_reader_id") {
        require_count(env, arguments, 2);
        auto reader_id = binary(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        df_buffer* output = nullptr;
        const auto status = df_commit_reader_id(context.card, reader_id.data, reader_id.size, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_create_application") {
        require_count(env, arguments, 6);
        auto aid = u32(env, argument(env, arguments, 0));
        auto key_settings = u32(env, argument(env, arguments, 1));
        auto key_count = u32(env, argument(env, arguments, 2));
        auto iso_id = i32(env, argument(env, arguments, 3));
        auto df_name = binary(env, argument(env, arguments, 4));
        auto timeout_ms = u32(env, argument(env, arguments, 5));
        const auto status = df_create_application(context.card, aid, key_settings, key_count, iso_id, df_name.data, df_name.size, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_create_data_file") {
        require_count(env, arguments, 7);
        auto file = u32(env, argument(env, arguments, 0));
        auto length = u32(env, argument(env, arguments, 1));
        auto communication = u32(env, argument(env, arguments, 2));
        auto access_rights = u32(env, argument(env, arguments, 3));
        auto iso_id = i32(env, argument(env, arguments, 4));
        auto backup = u32(env, argument(env, arguments, 5));
        auto timeout_ms = u32(env, argument(env, arguments, 6));
        const auto status = df_create_data_file(context.card, file, length, communication, access_rights, iso_id, backup, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_create_value_file") {
        require_count(env, arguments, 9);
        auto file = u32(env, argument(env, arguments, 0));
        auto lower_limit = i32(env, argument(env, arguments, 1));
        auto upper_limit = i32(env, argument(env, arguments, 2));
        auto initial_value = i32(env, argument(env, arguments, 3));
        auto communication = u32(env, argument(env, arguments, 4));
        auto access_rights = u32(env, argument(env, arguments, 5));
        auto limited_credit = u32(env, argument(env, arguments, 6));
        auto free_get_value = u32(env, argument(env, arguments, 7));
        auto timeout_ms = u32(env, argument(env, arguments, 8));
        const auto status = df_create_value_file(context.card, file, lower_limit, upper_limit, initial_value, communication, access_rights, limited_credit, free_get_value, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_create_record_file") {
        require_count(env, arguments, 8);
        auto file = u32(env, argument(env, arguments, 0));
        auto record_size = u32(env, argument(env, arguments, 1));
        auto maximum_records = u32(env, argument(env, arguments, 2));
        auto communication = u32(env, argument(env, arguments, 3));
        auto access_rights = u32(env, argument(env, arguments, 4));
        auto iso_id = i32(env, argument(env, arguments, 5));
        auto cyclic = u32(env, argument(env, arguments, 6));
        auto timeout_ms = u32(env, argument(env, arguments, 7));
        const auto status = df_create_record_file(context.card, file, record_size, maximum_records, communication, access_rights, iso_id, cyclic, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_change_file_settings") {
        require_count(env, arguments, 5);
        auto file = u32(env, argument(env, arguments, 0));
        auto communication = u32(env, argument(env, arguments, 1));
        auto access_rights = u32(env, argument(env, arguments, 2));
        auto command_communication = u32(env, argument(env, arguments, 3));
        auto timeout_ms = u32(env, argument(env, arguments, 4));
        const auto status = df_change_file_settings(context.card, file, communication, access_rights, command_communication, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_create_transaction_mac_file") {
        require_count(env, arguments, 5);
        auto file = u32(env, argument(env, arguments, 0));
        auto access_rights = u32(env, argument(env, arguments, 1));
        auto key = binary(env, argument(env, arguments, 2));
        auto version = u32(env, argument(env, arguments, 3));
        auto timeout_ms = u32(env, argument(env, arguments, 4));
        const auto status = df_create_transaction_mac_file(context.card, file, access_rights, key.data, key.size, version, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_change_aes_key") {
        require_count(env, arguments, 8);
        auto number = u32(env, argument(env, arguments, 0));
        auto new_key = binary(env, argument(env, arguments, 1));
        auto version = u32(env, argument(env, arguments, 2));
        auto authenticated_key = u32(env, argument(env, arguments, 3));
        auto old_key = binary(env, argument(env, arguments, 4));
        auto key_set = i32(env, argument(env, arguments, 5));
        auto picc_master = u32(env, argument(env, arguments, 6));
        auto timeout_ms = u32(env, argument(env, arguments, 7));
        const auto status = df_change_aes_key(context.card, number, new_key.data, new_key.size, version, authenticated_key, old_key.data, old_key.size, key_set, picc_master, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_iso_select_file") {
        require_count(env, arguments, 4);
        auto identifier = u32(env, argument(env, arguments, 0));
        auto selection = u32(env, argument(env, arguments, 1));
        auto response = u32(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        df_buffer* output = nullptr;
        const auto status = df_iso_select_file(context.card, identifier, selection, response, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_iso_select_df_name") {
        require_count(env, arguments, 3);
        auto name = binary(env, argument(env, arguments, 0));
        auto response = u32(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_iso_select_df_name(context.card, name.data, name.size, response, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_iso_read_binary") {
        require_count(env, arguments, 4);
        auto short_identifier = i32(env, argument(env, arguments, 0));
        auto offset = u32(env, argument(env, arguments, 1));
        auto length = u32(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        df_buffer* output = nullptr;
        const auto status = df_iso_read_binary(context.card, short_identifier, offset, length, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_iso_update_binary") {
        require_count(env, arguments, 4);
        auto short_identifier = i32(env, argument(env, arguments, 0));
        auto offset = u32(env, argument(env, arguments, 1));
        auto data = binary(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        df_buffer* output = nullptr;
        const auto status = df_iso_update_binary(context.card, short_identifier, offset, data.data, data.size, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_iso_read_records") {
        require_count(env, arguments, 5);
        auto record = u32(env, argument(env, arguments, 0));
        auto short_identifier = u32(env, argument(env, arguments, 1));
        auto selection = u32(env, argument(env, arguments, 2));
        auto length = u32(env, argument(env, arguments, 3));
        auto timeout_ms = u32(env, argument(env, arguments, 4));
        df_buffer* output = nullptr;
        const auto status = df_iso_read_records(context.card, record, short_identifier, selection, length, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_iso_append_record") {
        require_count(env, arguments, 3);
        auto short_identifier = u32(env, argument(env, arguments, 0));
        auto data = binary(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_iso_append_record(context.card, short_identifier, data.data, data.size, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_iso_get_challenge") {
        require_count(env, arguments, 2);
        auto length = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        df_buffer* output = nullptr;
        const auto status = df_iso_get_challenge(context.card, length, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_iso_external_authenticate") {
        require_count(env, arguments, 5);
        auto number = u32(env, argument(env, arguments, 0));
        auto application = u32(env, argument(env, arguments, 1));
        auto algorithm = u32(env, argument(env, arguments, 2));
        auto data = binary(env, argument(env, arguments, 3));
        auto timeout_ms = u32(env, argument(env, arguments, 4));
        df_buffer* output = nullptr;
        const auto status = df_iso_external_authenticate(context.card, number, application, algorithm, data.data, data.size, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_iso_internal_authenticate") {
        require_count(env, arguments, 5);
        auto number = u32(env, argument(env, arguments, 0));
        auto application = u32(env, argument(env, arguments, 1));
        auto algorithm = u32(env, argument(env, arguments, 2));
        auto data = binary(env, argument(env, arguments, 3));
        auto timeout_ms = u32(env, argument(env, arguments, 4));
        df_buffer* output = nullptr;
        const auto status = df_iso_internal_authenticate(context.card, number, application, algorithm, data.data, data.size, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_authenticate_iso_aes") {
        require_count(env, arguments, 4);
        auto number = u32(env, argument(env, arguments, 0));
        auto application = u32(env, argument(env, arguments, 1));
        auto key = binary(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        const auto status = df_authenticate_iso_aes(context.card, number, application, key.data, key.size, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_authenticate_ev2_first_aes") {
        require_count(env, arguments, 3);
        auto key_number = u32(env, argument(env, arguments, 0));
        auto key = binary(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        df_authentication_info_v1 out{};
        initialize_descriptor(out);
        const auto status = df_authenticate_ev2_first_aes(context.card, key_number, key.data, key.size, timeout_ms, &out, &error);
        check_native(env, status, error);
        return authentication_result(env, out);
    }
    if (operation == "df_authenticate_ev2_first_aes_with_capabilities") {
        require_count(env, arguments, 4);
        auto key_number = u32(env, argument(env, arguments, 0));
        auto key = binary(env, argument(env, arguments, 1));
        auto pcd_capabilities = binary(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        df_authentication_info_v1 out{};
        initialize_descriptor(out);
        const auto status = df_authenticate_ev2_first_aes_with_capabilities(context.card, key_number, key.data, key.size, pcd_capabilities.data, pcd_capabilities.size, timeout_ms, &out, &error);
        check_native(env, status, error);
        return authentication_result(env, out);
    }
    if (operation == "df_authenticate_ev2_non_first_aes") {
        require_count(env, arguments, 3);
        auto key_number = u32(env, argument(env, arguments, 0));
        auto key = binary(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        df_authentication_info_v1 out{};
        initialize_descriptor(out);
        const auto status = df_authenticate_ev2_non_first_aes(context.card, key_number, key.data, key.size, timeout_ms, &out, &error);
        check_native(env, status, error);
        return authentication_result(env, out);
    }
    if (operation == "df_get_df_names") {
        require_count(env, arguments, 1);
        auto timeout_ms = u32(env, argument(env, arguments, 0));
        df_buffer* output = nullptr;
        const auto status = df_get_df_names(context.card, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_reset_authentication") {
        require_count(env, arguments, 0);
        const auto status = df_reset_authentication(context.card, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_restore_transfer") {
        require_count(env, arguments, 4);
        auto target_file = u32(env, argument(env, arguments, 0));
        auto source_file = u32(env, argument(env, arguments, 1));
        auto communication = u32(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        const auto status = df_restore_transfer(context.card, target_file, source_file, communication, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_create_delegated_application") {
        require_count(env, arguments, 13);
        auto aid = u32(env, argument(env, arguments, 0));
        auto key_settings = u32(env, argument(env, arguments, 1));
        auto number_of_keys = u32(env, argument(env, arguments, 2));
        auto slot = u32(env, argument(env, arguments, 3));
        auto slot_version = u32(env, argument(env, arguments, 4));
        auto quota_limit = u32(env, argument(env, arguments, 5));
        auto iso_file_identifiers = u32(env, argument(env, arguments, 6));
        auto key_settings3 = i32(env, argument(env, arguments, 7));
        auto iso_id = i32(env, argument(env, arguments, 8));
        auto df_name = binary(env, argument(env, arguments, 9));
        auto encrypted_default_key = binary(env, argument(env, arguments, 10));
        auto dam_mac = binary(env, argument(env, arguments, 11));
        auto timeout_ms = u32(env, argument(env, arguments, 12));
        const auto status = df_create_delegated_application(context.card, aid, key_settings, number_of_keys, slot, slot_version, quota_limit, iso_file_identifiers, key_settings3, iso_id, df_name.data, df_name.size, encrypted_default_key.data, encrypted_default_key.size, dam_mac.data, dam_mac.size, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_get_delegated_application_info") {
        require_count(env, arguments, 2);
        auto slot = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        df_delegated_application_info_v1 output{};
        initialize_descriptor(output);
        const auto status = df_get_delegated_application_info(context.card, slot, timeout_ms, &output, &error);
        check_native(env, status, error);
        return delegated_result(env, output);
    }
    if (operation == "df_delete_delegated_application") {
        require_count(env, arguments, 3);
        auto aid = u32(env, argument(env, arguments, 0));
        auto dam_mac = binary(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        const auto status = df_delete_delegated_application(context.card, aid, dam_mac.data, dam_mac.size, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_get_card_uid_variant") {
        require_count(env, arguments, 2);
        auto option = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        df_buffer* output = nullptr;
        const auto status = df_get_card_uid_variant(context.card, option, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_set_picc_configuration") {
        require_count(env, arguments, 2);
        auto configuration = picc_configuration(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_set_picc_configuration(context.card, &configuration.value, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_set_capability_configuration") {
        require_count(env, arguments, 2);
        auto capabilities = binary(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_set_capability_configuration(context.card, capabilities.data, capabilities.size, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_set_default_aes_key") {
        require_count(env, arguments, 3);
        auto key = binary(env, argument(env, arguments, 0));
        auto key_version = u32(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        const auto status = df_set_default_aes_key(context.card, key.data, key.size, key_version, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_set_ats") {
        require_count(env, arguments, 2);
        auto ats = binary(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_set_ats(context.card, ats.data, ats.size, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_set_atqa") {
        require_count(env, arguments, 2);
        auto atqa = u32(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        const auto status = df_set_atqa(context.card, atqa, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_iso_update_record") {
        require_count(env, arguments, 6);
        auto instruction = u32(env, argument(env, arguments, 0));
        auto record = u32(env, argument(env, arguments, 1));
        auto short_identifier = u32(env, argument(env, arguments, 2));
        auto reference_control = u32(env, argument(env, arguments, 3));
        auto data = binary(env, argument(env, arguments, 4));
        auto timeout_ms = u32(env, argument(env, arguments, 5));
        df_buffer* output = nullptr;
        const auto status = df_iso_update_record(context.card, instruction, record, short_identifier, reference_control, data.data, data.size, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_execute_transaction") {
        require_count(env, arguments, 3);
        auto operations = transaction_plan(env, argument(env, arguments, 0));
        auto return_mac = u32(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_execute_transaction(context.card, operations.values.data(), operations.values.size(), return_mac, timeout_ms, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    throw BridgeFailure("Unknown managed C ABI operation");
}

napi_value dispatch_raw(napi_env env, Context& context, const std::string& operation,
                        napi_value arguments) {
    df_error error{};
    if (operation == "df_raw_native_frame") {
        require_count(env, arguments, 4);
        auto framing = u32(env, argument(env, arguments, 0));
        auto command = u32(env, argument(env, arguments, 1));
        auto data = binary(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        std::uint32_t native_status{};
        df_buffer* response = nullptr;
        const auto status = df_raw_native_frame(context.raw, framing, command, data.data, data.size, timeout_ms, &native_status, &response, &error);
        BufferOwner owned_response(response);
        check_native(env, status, error);
        return status_response(env, native_status, owned_response.get());
    }
    if (operation == "df_raw_native_exchange") {
        require_count(env, arguments, 2);
        auto request = native_request(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        std::uint32_t native_status{};
        df_buffer* response = nullptr;
        const auto status = df_raw_native_exchange(context.raw, &request.value, timeout_ms, &native_status, &response, &error);
        BufferOwner owned_response(response);
        check_native(env, status, error);
        return status_response(env, native_status, owned_response.get());
    }
    if (operation == "df_raw_iso_exchange") {
        require_count(env, arguments, 2);
        auto request = iso_apdu(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        std::uint32_t iso_status{};
        df_buffer* response = nullptr;
        const auto status = df_raw_iso_exchange(context.raw, &request.value, timeout_ms, &iso_status, &response, &error);
        BufferOwner owned_response(response);
        check_native(env, status, error);
        return status_response(env, iso_status, owned_response.get());
    }
    if (operation == "df_raw_authenticate_standard_aes") {
        require_count(env, arguments, 3);
        auto key_number = u32(env, argument(env, arguments, 0));
        auto key = binary(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        const auto status = df_raw_authenticate_standard_aes(context.raw, key_number, key.data, key.size, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_raw_authenticate_ev2_first_aes") {
        require_count(env, arguments, 4);
        auto key_number = u32(env, argument(env, arguments, 0));
        auto key = binary(env, argument(env, arguments, 1));
        auto pcd_capabilities = binary(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        df_authentication_info_v1 out{};
        initialize_descriptor(out);
        const auto status = df_raw_authenticate_ev2_first_aes(context.raw, key_number, key.data, key.size, pcd_capabilities.data, pcd_capabilities.size, timeout_ms, &out, &error);
        check_native(env, status, error);
        return authentication_result(env, out);
    }
    if (operation == "df_raw_authenticate_ev2_non_first_aes") {
        require_count(env, arguments, 3);
        auto key_number = u32(env, argument(env, arguments, 0));
        auto key = binary(env, argument(env, arguments, 1));
        auto timeout_ms = u32(env, argument(env, arguments, 2));
        df_authentication_info_v1 out{};
        initialize_descriptor(out);
        const auto status = df_raw_authenticate_ev2_non_first_aes(context.raw, key_number, key.data, key.size, timeout_ms, &out, &error);
        check_native(env, status, error);
        return authentication_result(env, out);
    }
    if (operation == "df_raw_authenticate_iso_aes") {
        require_count(env, arguments, 4);
        auto key_number = u32(env, argument(env, arguments, 0));
        auto application = u32(env, argument(env, arguments, 1));
        auto key = binary(env, argument(env, arguments, 2));
        auto timeout_ms = u32(env, argument(env, arguments, 3));
        const auto status = df_raw_authenticate_iso_aes(context.raw, key_number, application, key.data, key.size, timeout_ms, &error);
        check_native(env, status, error);
        return undefined(env);
    }
    if (operation == "df_raw_native_secure_exchange") {
        require_count(env, arguments, 2);
        auto request = native_secure_request(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        df_buffer* response = nullptr;
        const auto status = df_raw_native_secure_exchange(context.raw, &request.value, timeout_ms, &response, &error);
        BufferOwner owned_response(response);
        check_native(env, status, error);
        return buffer_result(env, owned_response.get());
    }
    if (operation == "df_raw_iso_secure_exchange") {
        require_count(env, arguments, 2);
        auto request = iso_apdu(env, argument(env, arguments, 0));
        auto timeout_ms = u32(env, argument(env, arguments, 1));
        std::uint32_t iso_status{};
        df_buffer* response = nullptr;
        const auto status = df_raw_iso_secure_exchange(context.raw, &request.value, timeout_ms, &iso_status, &response, &error);
        BufferOwner owned_response(response);
        check_native(env, status, error);
        return status_response(env, iso_status, owned_response.get());
    }
    throw BridgeFailure("Unknown raw C ABI operation");
}

napi_value dispatch_offline(napi_env env, const std::string& operation,
                            napi_value arguments) {
    df_error error{};
    if (operation == "df_offline_derive_nxp_aes128") {
        require_count(env, arguments, 2);
        auto master_key = binary(env, argument(env, arguments, 0));
        auto diversification = binary(env, argument(env, arguments, 1));
        df_buffer* output = nullptr;
        const auto status = df_offline_derive_nxp_aes128(master_key.data, master_key.size, diversification.data, diversification.size, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_offline_calculate_transaction_mac_aes") {
        require_count(env, arguments, 4);
        auto transaction_mac_key = binary(env, argument(env, arguments, 0));
        auto transaction_counter = u32(env, argument(env, arguments, 1));
        auto uid = binary(env, argument(env, arguments, 2));
        auto transaction_input = binary(env, argument(env, arguments, 3));
        df_buffer* output = nullptr;
        const auto status = df_offline_calculate_transaction_mac_aes(transaction_mac_key.data, transaction_mac_key.size, transaction_counter, uid.data, uid.size, transaction_input.data, transaction_input.size, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_offline_verify_originality_uid_signature") {
        require_count(env, arguments, 4);
        auto curve = string_value(env, argument(env, arguments, 0));
        auto public_key = binary(env, argument(env, arguments, 1));
        auto uid = binary(env, argument(env, arguments, 2));
        auto signature = binary(env, argument(env, arguments, 3));
        std::uint32_t verified{};
        const auto status = df_offline_verify_originality_uid_signature(curve.c_str(), public_key.data, public_key.size, uid.data, uid.size, signature.data, signature.size, &verified, &error);
        check_native(env, status, error);
        return boolean_result(env, verified != 0);
    }
    if (operation == "df_offline_encrypt_delegated_default_key_aes") {
        require_count(env, arguments, 3);
        auto dam_encryption_key = binary(env, argument(env, arguments, 0));
        auto application_default_key = binary(env, argument(env, arguments, 1));
        auto application_default_key_version = u32(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_offline_encrypt_delegated_default_key_aes(dam_encryption_key.data, dam_encryption_key.size, application_default_key.data, application_default_key.size, application_default_key_version, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_offline_calculate_delegated_application_mac_aes") {
        require_count(env, arguments, 3);
        auto dam_mac_key = binary(env, argument(env, arguments, 0));
        auto configuration = delegated_application_configuration(env, argument(env, arguments, 1));
        auto encrypted_default_key = binary(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_offline_calculate_delegated_application_mac_aes(dam_mac_key.data, dam_mac_key.size, &configuration.value, encrypted_default_key.data, encrypted_default_key.size, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_offline_calculate_delegated_application_delete_mac_aes") {
        require_count(env, arguments, 2);
        auto dam_mac_key = binary(env, argument(env, arguments, 0));
        auto application_id = u32(env, argument(env, arguments, 1));
        df_buffer* output = nullptr;
        const auto status = df_offline_calculate_delegated_application_delete_mac_aes(dam_mac_key.data, dam_mac_key.size, application_id, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_offline_calculate_delegated_configuration_mac_aes") {
        require_count(env, arguments, 3);
        auto dam_mac_key = binary(env, argument(env, arguments, 0));
        auto old_df_name = binary(env, argument(env, arguments, 1));
        auto new_df_name = binary(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_offline_calculate_delegated_configuration_mac_aes(dam_mac_key.data, dam_mac_key.size, old_df_name.data, old_df_name.size, new_df_name.data, new_df_name.size, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_offline_calculate_mfc_license_mac_aes") {
        require_count(env, arguments, 3);
        auto license_mac_key = binary(env, argument(env, arguments, 0));
        auto mfc_license = binary(env, argument(env, arguments, 1));
        auto mfc_sector_secrets = binary(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_offline_calculate_mfc_license_mac_aes(license_mac_key.data, license_mac_key.size, mfc_license.data, mfc_license.size, mfc_sector_secrets.data, mfc_sector_secrets.size, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_offline_derive_transaction_mac_keys_aes") {
        require_count(env, arguments, 3);
        auto transaction_key = binary(env, argument(env, arguments, 0));
        auto transaction_counter = u32(env, argument(env, arguments, 1));
        auto uid = binary(env, argument(env, arguments, 2));
        df_buffer* output = nullptr;
        const auto status = df_offline_derive_transaction_mac_keys_aes(transaction_key.data, transaction_key.size, transaction_counter, uid.data, uid.size, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_offline_calculate_transaction_mac_session_aes") {
        require_count(env, arguments, 2);
        auto session_mac_key = binary(env, argument(env, arguments, 0));
        auto transaction_input = binary(env, argument(env, arguments, 1));
        df_buffer* output = nullptr;
        const auto status = df_offline_calculate_transaction_mac_session_aes(session_mac_key.data, session_mac_key.size, transaction_input.data, transaction_input.size, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    if (operation == "df_offline_verify_transaction_mac_aes") {
        require_count(env, arguments, 5);
        auto transaction_key = binary(env, argument(env, arguments, 0));
        auto transaction_counter = u32(env, argument(env, arguments, 1));
        auto uid = binary(env, argument(env, arguments, 2));
        auto transaction_input = binary(env, argument(env, arguments, 3));
        auto transaction_mac = binary(env, argument(env, arguments, 4));
        std::uint32_t verified{};
        const auto status = df_offline_verify_transaction_mac_aes(transaction_key.data, transaction_key.size, transaction_counter, uid.data, uid.size, transaction_input.data, transaction_input.size, transaction_mac.data, transaction_mac.size, &verified, &error);
        check_native(env, status, error);
        return boolean_result(env, verified != 0);
    }
    if (operation == "df_offline_decrypt_transaction_reader_id_aes") {
        require_count(env, arguments, 2);
        auto session_encryption_key = binary(env, argument(env, arguments, 0));
        auto encrypted_reader_id = binary(env, argument(env, arguments, 1));
        df_buffer* output = nullptr;
        const auto status = df_offline_decrypt_transaction_reader_id_aes(session_encryption_key.data, session_encryption_key.size, encrypted_reader_id.data, encrypted_reader_id.size, &output, &error);
        BufferOwner owned_output(output);
        check_native(env, status, error);
        return buffer_result(env, owned_output.get());
    }
    throw BridgeFailure("Unknown offline C ABI operation");
}
