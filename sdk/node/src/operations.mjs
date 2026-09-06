/** Generated from api/ev3-api.json; contains no protocol encoding. */
export const MANIFEST_SHA256 = "15bff2b3d371174e8b26350f95b2f6589149b50fab11652ec181961015416596";
export const operations = Object.freeze({
  "get_version": {
    "id": 1006,
    "native": "df_get_version",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read the complete 28-byte native GetVersion payload."
  },
  "free_memory": {
    "id": 1007,
    "native": "df_free_memory",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "uint32",
    "mutation": false,
    "summary": "Read the available PICC storage in bytes."
  },
  "select_application": {
    "id": 1008,
    "native": "df_select_application",
    "surface": "managed",
    "arguments": [
      {
        "name": "aid",
        "kind": "u32",
        "maximum": 16777215
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": false,
    "summary": "Select a native application and replace the previous authentication context."
  },
  "file_ids": {
    "id": 1009,
    "native": "df_file_ids",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read one native file number per returned byte."
  },
  "authenticate_standard_aes": {
    "id": 1010,
    "native": "df_authenticate_standard_aes",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": false,
    "summary": "Establish Standard AES authentication with one borrowed exact key."
  },
  "application_ids": {
    "id": 1011,
    "native": "df_application_ids",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read application identifiers as consecutive three-byte little-endian values."
  },
  "iso_file_ids": {
    "id": 1012,
    "native": "df_iso_file_ids",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read native GetISOFileIDs output as consecutive two-byte little-endian identifiers."
  },
  "get_key_settings": {
    "id": 1013,
    "native": "df_get_key_settings",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read the selected application key-settings payload in native wire order."
  },
  "get_key_set_versions": {
    "id": 1014,
    "native": "df_get_key_set_versions",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read the selected application key-set version payload in native wire order."
  },
  "get_card_uid": {
    "id": 1015,
    "native": "df_get_card_uid",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read the real card UID through the authenticated native command."
  },
  "read_originality_signature": {
    "id": 1016,
    "native": "df_read_originality_signature",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read the raw originality signature for separate trusted-key verification."
  },
  "abort_transaction": {
    "id": 1017,
    "native": "df_abort_transaction",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Abort the card transaction currently pending in the selected application."
  },
  "format_picc": {
    "id": 1018,
    "native": "df_format_picc",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Execute the authenticated PICC format operation and invalidate the session."
  },
  "delete_file": {
    "id": 1019,
    "native": "df_delete_file",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Delete one file from the selected application."
  },
  "get_file_settings": {
    "id": 1020,
    "native": "df_get_file_settings",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read a validated native file-settings payload in wire order."
  },
  "clear_record_file": {
    "id": 1021,
    "native": "df_clear_record_file",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Stage removal of all records in the selected record file."
  },
  "get_file_counters": {
    "id": 1022,
    "native": "df_get_file_counters",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read three little-endian SDM counter bytes followed by two reserved bytes."
  },
  "delete_application": {
    "id": 1023,
    "native": "df_delete_application",
    "surface": "managed",
    "arguments": [
      {
        "name": "aid",
        "kind": "u32",
        "maximum": 16777215
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Delete a nonzero native application identifier."
  },
  "change_key_settings": {
    "id": 1024,
    "native": "df_change_key_settings",
    "surface": "managed",
    "arguments": [
      {
        "name": "settings",
        "kind": "u32"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Change the selected application key-settings byte."
  },
  "get_key_version": {
    "id": 1025,
    "native": "df_get_key_version",
    "surface": "managed",
    "arguments": [
      {
        "name": "number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "key_set",
        "kind": "i32"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read the version payload for one native key and optional key set."
  },
  "initialize_key_set": {
    "id": 1026,
    "native": "df_initialize_key_set",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_set",
        "kind": "u32",
        "maximum": 15
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Initialize the selected EV3 key set."
  },
  "roll_key_set": {
    "id": 1027,
    "native": "df_roll_key_set",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_set",
        "kind": "u32",
        "maximum": 15
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Activate the requested EV3 key set and invalidate the old authentication context."
  },
  "finalize_key_set": {
    "id": 1028,
    "native": "df_finalize_key_set",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_set",
        "kind": "u32",
        "maximum": 15
      },
      {
        "name": "version",
        "kind": "u32",
        "maximum": 255
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Finalize an EV3 key set with its version byte."
  },
  "read_data": {
    "id": 1029,
    "native": "df_read_data",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "offset",
        "kind": "u32"
      },
      {
        "name": "length",
        "kind": "u32"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read native data-file bytes using the selected communication mode."
  },
  "write_data": {
    "id": 1030,
    "native": "df_write_data",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "offset",
        "kind": "u32"
      },
      {
        "name": "data",
        "kind": "bytes"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Write native data-file bytes; backup-file writes remain pending until commit."
  },
  "write_record": {
    "id": 1031,
    "native": "df_write_record",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "offset",
        "kind": "u32"
      },
      {
        "name": "data",
        "kind": "bytes"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Stage bytes in a native record file at a byte offset."
  },
  "read_records": {
    "id": 1032,
    "native": "df_read_records",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "first",
        "kind": "u32"
      },
      {
        "name": "count",
        "kind": "u32"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read native record-file content from the specified record index."
  },
  "update_record": {
    "id": 1033,
    "native": "df_update_record",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "record",
        "kind": "u32"
      },
      {
        "name": "offset",
        "kind": "u32"
      },
      {
        "name": "data",
        "kind": "bytes"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Stage replacement bytes within one native record."
  },
  "credit": {
    "id": 1034,
    "native": "df_credit",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "amount",
        "kind": "u32"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Stage an increase to a native value file."
  },
  "debit": {
    "id": 1035,
    "native": "df_debit",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "amount",
        "kind": "u32"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Stage a decrease to a native value file."
  },
  "limited_credit": {
    "id": 1036,
    "native": "df_limited_credit",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "amount",
        "kind": "u32"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Stage a limited-credit increase permitted by the value-file policy."
  },
  "get_value": {
    "id": 1037,
    "native": "df_get_value",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "int32",
    "mutation": false,
    "summary": "Read the signed value of a native value file."
  },
  "commit_transaction": {
    "id": 1038,
    "native": "df_commit_transaction",
    "surface": "managed",
    "arguments": [
      {
        "name": "return_mac",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": true,
    "summary": "Commit staged changes and optionally return the transaction MAC evidence."
  },
  "commit_reader_id": {
    "id": 1039,
    "native": "df_commit_reader_id",
    "surface": "managed",
    "arguments": [
      {
        "name": "reader_id",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": true,
    "summary": "Submit a sixteen-byte ReaderID and return the previous encrypted ReaderID."
  },
  "create_application": {
    "id": 1040,
    "native": "df_create_application",
    "surface": "managed",
    "arguments": [
      {
        "name": "aid",
        "kind": "u32",
        "maximum": 16777215
      },
      {
        "name": "key_settings",
        "kind": "u32"
      },
      {
        "name": "key_count",
        "kind": "u32"
      },
      {
        "name": "iso_id",
        "kind": "i32"
      },
      {
        "name": "df_name",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Create an AES application with optional ISO selection identifiers."
  },
  "create_data_file": {
    "id": 1041,
    "native": "df_create_data_file",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "length",
        "kind": "u32"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "access_rights",
        "kind": "u32"
      },
      {
        "name": "iso_id",
        "kind": "i32"
      },
      {
        "name": "backup",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Create a standard or backup native data file."
  },
  "create_value_file": {
    "id": 1042,
    "native": "df_create_value_file",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "lower_limit",
        "kind": "i32"
      },
      {
        "name": "upper_limit",
        "kind": "i32"
      },
      {
        "name": "initial_value",
        "kind": "i32"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "access_rights",
        "kind": "u32"
      },
      {
        "name": "limited_credit",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "free_get_value",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Create a native value file with explicit signed limits and initial value."
  },
  "create_record_file": {
    "id": 1043,
    "native": "df_create_record_file",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "record_size",
        "kind": "u32"
      },
      {
        "name": "maximum_records",
        "kind": "u32"
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "access_rights",
        "kind": "u32"
      },
      {
        "name": "iso_id",
        "kind": "i32"
      },
      {
        "name": "cyclic",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Create a linear or cyclic native record file."
  },
  "change_file_settings": {
    "id": 1044,
    "native": "df_change_file_settings",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "access_rights",
        "kind": "u32"
      },
      {
        "name": "command_communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Change file communication and access rights under the current command policy."
  },
  "create_transaction_mac_file": {
    "id": 1045,
    "native": "df_create_transaction_mac_file",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "access_rights",
        "kind": "u32"
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "version",
        "kind": "u32",
        "maximum": 255
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Create an AES transaction-MAC file with an explicit backend key."
  },
  "change_aes_key": {
    "id": 1046,
    "native": "df_change_aes_key",
    "surface": "managed",
    "arguments": [
      {
        "name": "number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "new_key",
        "kind": "bytes"
      },
      {
        "name": "version",
        "kind": "u32",
        "maximum": 255
      },
      {
        "name": "authenticated_key",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "old_key",
        "kind": "bytes"
      },
      {
        "name": "key_set",
        "kind": "i32"
      },
      {
        "name": "picc_master",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Replace an AES key using the verified current authentication selector."
  },
  "iso_select_file": {
    "id": 1047,
    "native": "df_iso_select_file",
    "surface": "managed",
    "arguments": [
      {
        "name": "identifier",
        "kind": "u32"
      },
      {
        "name": "selection",
        "kind": "u32"
      },
      {
        "name": "response",
        "kind": "u32"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Select an ISO file with CLA 00 and optionally return its FCI bytes."
  },
  "iso_select_df_name": {
    "id": 1048,
    "native": "df_iso_select_df_name",
    "surface": "managed",
    "arguments": [
      {
        "name": "name",
        "kind": "bytes"
      },
      {
        "name": "response",
        "kind": "u32"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Select an ISO DF by name and replace the prior authentication context."
  },
  "iso_read_binary": {
    "id": 1049,
    "native": "df_iso_read_binary",
    "surface": "managed",
    "arguments": [
      {
        "name": "short_identifier",
        "kind": "i32"
      },
      {
        "name": "offset",
        "kind": "u32"
      },
      {
        "name": "length",
        "kind": "u32"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read ISO binary content, checking response CMAC when ISO AES is active."
  },
  "iso_update_binary": {
    "id": 1050,
    "native": "df_iso_update_binary",
    "surface": "managed",
    "arguments": [
      {
        "name": "short_identifier",
        "kind": "i32"
      },
      {
        "name": "offset",
        "kind": "u32"
      },
      {
        "name": "data",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": true,
    "summary": "Update ISO binary content using the current ISO authentication state."
  },
  "iso_read_records": {
    "id": 1051,
    "native": "df_iso_read_records",
    "surface": "managed",
    "arguments": [
      {
        "name": "record",
        "kind": "u32"
      },
      {
        "name": "short_identifier",
        "kind": "u32"
      },
      {
        "name": "selection",
        "kind": "u32"
      },
      {
        "name": "length",
        "kind": "u32"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read ISO records, checking response CMAC when ISO AES is active."
  },
  "iso_append_record": {
    "id": 1052,
    "native": "df_iso_append_record",
    "surface": "managed",
    "arguments": [
      {
        "name": "short_identifier",
        "kind": "u32"
      },
      {
        "name": "data",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": true,
    "summary": "Append a record with an ISO CLA 00 command."
  },
  "iso_get_challenge": {
    "id": 1053,
    "native": "df_iso_get_challenge",
    "surface": "managed",
    "arguments": [
      {
        "name": "length",
        "kind": "u32"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read an ISO challenge without establishing a verified SDK session."
  },
  "iso_external_authenticate": {
    "id": 1054,
    "native": "df_iso_external_authenticate",
    "surface": "managed",
    "arguments": [
      {
        "name": "number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "application",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "algorithm",
        "kind": "u32"
      },
      {
        "name": "data",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Send a caller-prepared ISO authentication cryptogram without establishing SDK trust."
  },
  "iso_internal_authenticate": {
    "id": 1055,
    "native": "df_iso_internal_authenticate",
    "surface": "managed",
    "arguments": [
      {
        "name": "number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "application",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "algorithm",
        "kind": "u32"
      },
      {
        "name": "data",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Send a caller-prepared ISO challenge without verifying the returned card proof."
  },
  "authenticate_iso_aes": {
    "id": 1056,
    "native": "df_authenticate_iso_aes",
    "surface": "managed",
    "arguments": [
      {
        "name": "number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "application",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": false,
    "summary": "Verify the complete ISO mutual AES proof and establish private response-MAC state."
  },
  "authenticate_standard_aes_provider": {
    "id": 1057,
    "native": "df_authenticate_standard_aes_provider",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": false,
    "summary": "Resolve exactly one key and establish Standard AES before card I/O.",
    "providerDirect": "authenticate_standard_aes"
  },
  "authenticate_ev2_first_aes": {
    "id": 1058,
    "native": "df_authenticate_ev2_first_aes",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Establish EV2 First with no PCD capability bytes and return verified metadata."
  },
  "authenticate_ev2_first_aes_provider": {
    "id": 1059,
    "native": "df_authenticate_ev2_first_aes_provider",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Resolve exactly one key, establish EV2 First, and return verified metadata.",
    "providerDirect": "authenticate_ev2_first_aes"
  },
  "authenticate_ev2_first_aes_with_capabilities": {
    "id": 1060,
    "native": "df_authenticate_ev2_first_aes_with_capabilities",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "pcd_capabilities",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Establish EV2 First with zero through six PCD capability bytes."
  },
  "authenticate_ev2_first_aes_with_capabilities_provider": {
    "id": 1061,
    "native": "df_authenticate_ev2_first_aes_with_capabilities_provider",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "pcd_capabilities",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Resolve exactly one key and establish EV2 First with explicit capabilities.",
    "providerDirect": "authenticate_ev2_first_aes_with_capabilities"
  },
  "authenticate_ev2_non_first_aes": {
    "id": 1062,
    "native": "df_authenticate_ev2_non_first_aes",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Replace an active EV2 session through NonFirst using one exact key."
  },
  "authenticate_ev2_non_first_aes_provider": {
    "id": 1063,
    "native": "df_authenticate_ev2_non_first_aes_provider",
    "surface": "managed",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Resolve exactly one key and replace an active EV2 session through NonFirst.",
    "providerDirect": "authenticate_ev2_non_first_aes"
  },
  "authenticate_iso_aes_provider": {
    "id": 1064,
    "native": "df_authenticate_iso_aes_provider",
    "surface": "managed",
    "arguments": [
      {
        "name": "number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "application",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": false,
    "summary": "Resolve exactly one key and establish ISO AES before the first APDU.",
    "providerDirect": "authenticate_iso_aes"
  },
  "get_df_names": {
    "id": 1065,
    "native": "df_get_df_names",
    "surface": "managed",
    "arguments": [
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read validated GetDFNames records as AID-LE3, ISO-ID-BE2, length, and name tuples."
  },
  "reset_authentication": {
    "id": 1066,
    "native": "df_reset_authentication",
    "surface": "managed",
    "arguments": [],
    "output": "void",
    "mutation": false,
    "summary": "Erase managed authentication locally without performing card I/O."
  },
  "restore_transfer": {
    "id": 1067,
    "native": "df_restore_transfer",
    "surface": "managed",
    "arguments": [
      {
        "name": "target_file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "source_file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "communication",
        "kind": "u32",
        "maximum": 3
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Stage a MIFARE Classic RestoreTransfer between two checked value files."
  },
  "create_delegated_application": {
    "id": 1068,
    "native": "df_create_delegated_application",
    "surface": "managed",
    "arguments": [
      {
        "name": "aid",
        "kind": "u32",
        "maximum": 16777215
      },
      {
        "name": "key_settings",
        "kind": "u32"
      },
      {
        "name": "number_of_keys",
        "kind": "u32"
      },
      {
        "name": "slot",
        "kind": "u32",
        "maximum": 65535
      },
      {
        "name": "slot_version",
        "kind": "u32",
        "maximum": 255
      },
      {
        "name": "quota_limit",
        "kind": "u32",
        "maximum": 65535
      },
      {
        "name": "iso_file_identifiers",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "key_settings3",
        "kind": "i32"
      },
      {
        "name": "iso_id",
        "kind": "i32"
      },
      {
        "name": "df_name",
        "kind": "bytes"
      },
      {
        "name": "encrypted_default_key",
        "kind": "bytes"
      },
      {
        "name": "dam_mac",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Create one checked delegated AES application with exact issuer authorization bytes."
  },
  "get_delegated_application_info": {
    "id": 1069,
    "native": "df_get_delegated_application_info",
    "surface": "managed",
    "arguments": [
      {
        "name": "slot",
        "kind": "u32",
        "maximum": 65535
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "delegated_application_info",
    "mutation": false,
    "summary": "Read and decode one delegated-application slot."
  },
  "delete_delegated_application": {
    "id": 1070,
    "native": "df_delete_delegated_application",
    "surface": "managed",
    "arguments": [
      {
        "name": "aid",
        "kind": "u32",
        "maximum": 16777215
      },
      {
        "name": "dam_mac",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Delete one delegated application using an exact issuer-generated DAM MAC."
  },
  "get_card_uid_variant": {
    "id": 1071,
    "native": "df_get_card_uid_variant",
    "surface": "managed",
    "arguments": [
      {
        "name": "option",
        "kind": "u32"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Read UID and optional four-byte NUID with one explicit documented request option."
  },
  "set_picc_configuration": {
    "id": 1072,
    "native": "df_set_picc_configuration",
    "surface": "managed",
    "arguments": [
      {
        "name": "configuration",
        "kind": "picc_configuration"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Set documented PICC option-zero flags using a versioned descriptor."
  },
  "set_capability_configuration": {
    "id": 1073,
    "native": "df_set_capability_configuration",
    "surface": "managed",
    "arguments": [
      {
        "name": "capabilities",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Set the exact nine-byte option-five capability record."
  },
  "set_default_aes_key": {
    "id": 1074,
    "native": "df_set_default_aes_key",
    "surface": "managed",
    "arguments": [
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "key_version",
        "kind": "u32",
        "maximum": 255
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Set the default application AES key and its version."
  },
  "set_default_aes_key_provider": {
    "id": 1075,
    "native": "df_set_default_aes_key_provider",
    "surface": "managed",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "key_version",
        "kind": "u32",
        "maximum": 255
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Resolve exactly one replacement key and set the default application AES key.",
    "providerDirect": "set_default_aes_key"
  },
  "set_ats": {
    "id": 1076,
    "native": "df_set_ats",
    "surface": "managed",
    "arguments": [
      {
        "name": "ats",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Set a complete two-through-twenty-byte ATS including its length byte."
  },
  "set_atqa": {
    "id": 1077,
    "native": "df_set_atqa",
    "surface": "managed",
    "arguments": [
      {
        "name": "atqa",
        "kind": "u32",
        "maximum": 65535
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Set the two-byte user ATQA value."
  },
  "iso_update_record": {
    "id": 1078,
    "native": "df_iso_update_record",
    "surface": "managed",
    "arguments": [
      {
        "name": "instruction",
        "kind": "u32"
      },
      {
        "name": "record",
        "kind": "u32"
      },
      {
        "name": "short_identifier",
        "kind": "u32"
      },
      {
        "name": "reference_control",
        "kind": "u32"
      },
      {
        "name": "data",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": true,
    "summary": "Execute the documented ISO UPDATE RECORD 0xDC or 0xDD variant."
  },
  "execute_transaction": {
    "id": 1079,
    "native": "df_execute_transaction",
    "surface": "managed",
    "arguments": [
      {
        "name": "operations",
        "kind": "transaction_operations"
      },
      {
        "name": "return_mac",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": true,
    "summary": "Execute one through 128 checked mutations and one explicit commit under one lock."
  },
  "change_aes_key_provider": {
    "id": 1080,
    "native": "df_change_aes_key_provider",
    "surface": "managed",
    "arguments": [
      {
        "name": "number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "new_key_source",
        "kind": "key_source"
      },
      {
        "name": "version",
        "kind": "u32",
        "maximum": 255
      },
      {
        "name": "authenticated_key",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "old_key_source",
        "kind": "key_source"
      },
      {
        "name": "key_set",
        "kind": "i32"
      },
      {
        "name": "picc_master",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Resolve new and optional old AES keys before changing one native key.",
    "providerDirect": "change_aes_key"
  },
  "create_transaction_mac_file_provider": {
    "id": 1081,
    "native": "df_create_transaction_mac_file_provider",
    "surface": "managed",
    "arguments": [
      {
        "name": "file",
        "kind": "u32",
        "maximum": 31
      },
      {
        "name": "access_rights",
        "kind": "u32"
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "version",
        "kind": "u32",
        "maximum": 255
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": true,
    "summary": "Resolve one AES key before creating a transaction-MAC file.",
    "providerDirect": "create_transaction_mac_file"
  },
  "raw_native_frame": {
    "id": 1087,
    "native": "df_raw_native_frame",
    "surface": "raw",
    "arguments": [
      {
        "name": "framing",
        "kind": "u32"
      },
      {
        "name": "command",
        "kind": "u32",
        "maximum": 255
      },
      {
        "name": "data",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "native_response",
    "mutation": true,
    "summary": "Exchange exactly one native physical frame and preserve its status byte."
  },
  "raw_native_exchange": {
    "id": 1088,
    "native": "df_raw_native_exchange",
    "surface": "raw",
    "arguments": [
      {
        "name": "request",
        "kind": "native_request"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "native_response",
    "mutation": true,
    "summary": "Exchange a bounded native logical command including explicitly requested AF chaining."
  },
  "raw_iso_exchange": {
    "id": 1089,
    "native": "df_raw_iso_exchange",
    "surface": "raw",
    "arguments": [
      {
        "name": "request",
        "kind": "iso_apdu"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "iso_response",
    "mutation": true,
    "summary": "Exchange one true ISO APDU and preserve the exact final 16-bit status word."
  },
  "raw_authenticate_standard_aes": {
    "id": 1090,
    "native": "df_raw_authenticate_standard_aes",
    "surface": "raw",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": false,
    "summary": "Install a Standard AES session on a native raw channel using one exact key."
  },
  "raw_authenticate_standard_aes_provider": {
    "id": 1091,
    "native": "df_raw_authenticate_standard_aes_provider",
    "surface": "raw",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": false,
    "summary": "Resolve exactly one key and install a Standard AES raw session.",
    "providerDirect": "raw_authenticate_standard_aes"
  },
  "raw_authenticate_ev2_first_aes": {
    "id": 1092,
    "native": "df_raw_authenticate_ev2_first_aes",
    "surface": "raw",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "pcd_capabilities",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Install EV2 First on a native raw channel and return verified public metadata."
  },
  "raw_authenticate_ev2_first_aes_provider": {
    "id": 1093,
    "native": "df_raw_authenticate_ev2_first_aes_provider",
    "surface": "raw",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "pcd_capabilities",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Resolve one key and install EV2 First with zero through six capability bytes.",
    "providerDirect": "raw_authenticate_ev2_first_aes"
  },
  "raw_authenticate_ev2_non_first_aes": {
    "id": 1094,
    "native": "df_raw_authenticate_ev2_non_first_aes",
    "surface": "raw",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Replace a raw EV2 session through NonFirst while preserving TI and counter."
  },
  "raw_authenticate_ev2_non_first_aes_provider": {
    "id": 1095,
    "native": "df_raw_authenticate_ev2_non_first_aes_provider",
    "surface": "raw",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "authentication_info",
    "mutation": false,
    "summary": "Resolve exactly one key and replace a raw EV2 session through NonFirst.",
    "providerDirect": "raw_authenticate_ev2_non_first_aes"
  },
  "raw_authenticate_iso_aes": {
    "id": 1096,
    "native": "df_raw_authenticate_iso_aes",
    "surface": "raw",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "application",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "key",
        "kind": "bytes"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": false,
    "summary": "Establish a verified ISO mutual AES session on an ISO raw channel."
  },
  "raw_authenticate_iso_aes_provider": {
    "id": 1097,
    "native": "df_raw_authenticate_iso_aes_provider",
    "surface": "raw",
    "arguments": [
      {
        "name": "key_number",
        "kind": "u32",
        "maximum": 63
      },
      {
        "name": "application",
        "kind": "boolean",
        "maximum": 1
      },
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "void",
    "mutation": false,
    "summary": "Resolve exactly one key and establish ISO mutual AES on an ISO raw channel.",
    "providerDirect": "raw_authenticate_iso_aes"
  },
  "raw_native_secure_exchange": {
    "id": 1098,
    "native": "df_raw_native_secure_exchange",
    "surface": "raw",
    "arguments": [
      {
        "name": "request",
        "kind": "native_secure_request"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "bytes",
    "mutation": true,
    "summary": "Execute one explicit secure-native request using its selected active raw session."
  },
  "offline_derive_nxp_aes128": {
    "id": 1099,
    "native": "df_offline_derive_nxp_aes128",
    "surface": "offline",
    "arguments": [
      {
        "name": "master_key",
        "kind": "bytes"
      },
      {
        "name": "diversification",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Derive one AES-128 key with NXP AN10922 from one through 31 explicit bytes."
  },
  "offline_derive_nxp_aes128_provider": {
    "id": 1100,
    "native": "df_offline_derive_nxp_aes128_provider",
    "surface": "offline",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Resolve one master key and derive AES-128 from the request's diversification bytes.",
    "providerDirect": "offline_derive_nxp_aes128"
  },
  "offline_calculate_transaction_mac_aes": {
    "id": 1101,
    "native": "df_offline_calculate_transaction_mac_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "transaction_mac_key",
        "kind": "bytes"
      },
      {
        "name": "transaction_counter",
        "kind": "u32"
      },
      {
        "name": "uid",
        "kind": "bytes"
      },
      {
        "name": "transaction_input",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Calculate an eight-byte AES transaction MAC from explicit counter, UID, and TMI."
  },
  "offline_calculate_transaction_mac_aes_provider": {
    "id": 1102,
    "native": "df_offline_calculate_transaction_mac_aes_provider",
    "surface": "offline",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "transaction_counter",
        "kind": "u32"
      },
      {
        "name": "uid",
        "kind": "bytes"
      },
      {
        "name": "transaction_input",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Resolve one transaction key and calculate the eight-byte AES transaction MAC.",
    "providerDirect": "offline_calculate_transaction_mac_aes"
  },
  "offline_verify_originality_uid_signature": {
    "id": 1103,
    "native": "df_offline_verify_originality_uid_signature",
    "surface": "offline",
    "arguments": [
      {
        "name": "curve",
        "kind": "string"
      },
      {
        "name": "public_key",
        "kind": "bytes"
      },
      {
        "name": "uid",
        "kind": "bytes"
      },
      {
        "name": "signature",
        "kind": "bytes"
      }
    ],
    "output": "boolean",
    "mutation": false,
    "summary": "Verify one UID originality signature using a caller-selected supported curve."
  },
  "raw_iso_secure_exchange": {
    "id": 1104,
    "native": "df_raw_iso_secure_exchange",
    "surface": "raw",
    "arguments": [
      {
        "name": "request",
        "kind": "iso_apdu"
      },
      {
        "name": "timeout_ms",
        "kind": "timeout",
        "minimum": 1
      }
    ],
    "output": "iso_response",
    "mutation": true,
    "summary": "Execute a checked ISO data command or EF selection through the active raw ISO AES session."
  },
  "offline_encrypt_delegated_default_key_aes": {
    "id": 1105,
    "native": "df_offline_encrypt_delegated_default_key_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "dam_encryption_key",
        "kind": "bytes"
      },
      {
        "name": "application_default_key",
        "kind": "bytes"
      },
      {
        "name": "application_default_key_version",
        "kind": "u32",
        "maximum": 255
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Encrypt a delegated application default AES key into the documented 32-byte EncK record."
  },
  "offline_encrypt_delegated_default_key_aes_provider": {
    "id": 1106,
    "native": "df_offline_encrypt_delegated_default_key_aes_provider",
    "surface": "offline",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "application_default_key",
        "kind": "bytes"
      },
      {
        "name": "application_default_key_version",
        "kind": "u32",
        "maximum": 255
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Resolve DAMEncKey before encrypting a caller-supplied delegated application default AES key.",
    "providerDirect": "offline_encrypt_delegated_default_key_aes"
  },
  "offline_calculate_delegated_application_mac_aes": {
    "id": 1107,
    "native": "df_offline_calculate_delegated_application_mac_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "dam_mac_key",
        "kind": "bytes"
      },
      {
        "name": "configuration",
        "kind": "delegated_application_configuration"
      },
      {
        "name": "encrypted_default_key",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Calculate the eight-byte delegated application creation MAC over one exact versioned configuration and EncK."
  },
  "offline_calculate_delegated_application_mac_aes_provider": {
    "id": 1108,
    "native": "df_offline_calculate_delegated_application_mac_aes_provider",
    "surface": "offline",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "configuration",
        "kind": "delegated_application_configuration"
      },
      {
        "name": "encrypted_default_key",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Resolve DAMMACKey before calculating the delegated application creation MAC.",
    "providerDirect": "offline_calculate_delegated_application_mac_aes"
  },
  "offline_calculate_delegated_application_delete_mac_aes": {
    "id": 1109,
    "native": "df_offline_calculate_delegated_application_delete_mac_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "dam_mac_key",
        "kind": "bytes"
      },
      {
        "name": "application_id",
        "kind": "u32",
        "maximum": 16777215
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Calculate the eight-byte issuer MAC authorizing deletion of one delegated application."
  },
  "offline_calculate_delegated_application_delete_mac_aes_provider": {
    "id": 1110,
    "native": "df_offline_calculate_delegated_application_delete_mac_aes_provider",
    "surface": "offline",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "application_id",
        "kind": "u32",
        "maximum": 16777215
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Resolve DAMMACKey before calculating the delegated application deletion MAC.",
    "providerDirect": "offline_calculate_delegated_application_delete_mac_aes"
  },
  "offline_calculate_delegated_configuration_mac_aes": {
    "id": 1111,
    "native": "df_offline_calculate_delegated_configuration_mac_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "dam_mac_key",
        "kind": "bytes"
      },
      {
        "name": "old_df_name",
        "kind": "bytes"
      },
      {
        "name": "new_df_name",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Calculate the eight-byte DAM MAC over explicit old and replacement DF names."
  },
  "offline_calculate_delegated_configuration_mac_aes_provider": {
    "id": 1112,
    "native": "df_offline_calculate_delegated_configuration_mac_aes_provider",
    "surface": "offline",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "old_df_name",
        "kind": "bytes"
      },
      {
        "name": "new_df_name",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Resolve DAMMACKey before calculating the delegated DF-name configuration MAC.",
    "providerDirect": "offline_calculate_delegated_configuration_mac_aes"
  },
  "offline_calculate_mfc_license_mac_aes": {
    "id": 1113,
    "native": "df_offline_calculate_mfc_license_mac_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "license_mac_key",
        "kind": "bytes"
      },
      {
        "name": "mfc_license",
        "kind": "bytes"
      },
      {
        "name": "mfc_sector_secrets",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Calculate the eight-byte AES MAC for one complete MIFARE Classic license and sector-secret record."
  },
  "offline_calculate_mfc_license_mac_aes_provider": {
    "id": 1114,
    "native": "df_offline_calculate_mfc_license_mac_aes_provider",
    "surface": "offline",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "mfc_license",
        "kind": "bytes"
      },
      {
        "name": "mfc_sector_secrets",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Resolve MFCLicenseMACKey before calculating the MIFARE Classic compatibility-license MAC.",
    "providerDirect": "offline_calculate_mfc_license_mac_aes"
  },
  "offline_derive_transaction_mac_keys_aes": {
    "id": 1115,
    "native": "df_offline_derive_transaction_mac_keys_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "transaction_key",
        "kind": "bytes"
      },
      {
        "name": "transaction_counter",
        "kind": "u32"
      },
      {
        "name": "uid",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Derive SesTMMACKey followed by SesTMENCKey into one exact 32-byte result."
  },
  "offline_derive_transaction_mac_keys_aes_provider": {
    "id": 1116,
    "native": "df_offline_derive_transaction_mac_keys_aes_provider",
    "surface": "offline",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "transaction_counter",
        "kind": "u32"
      },
      {
        "name": "uid",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Resolve AppTransactionMACKey before deriving both transaction session keys.",
    "providerDirect": "offline_derive_transaction_mac_keys_aes"
  },
  "offline_calculate_transaction_mac_session_aes": {
    "id": 1117,
    "native": "df_offline_calculate_transaction_mac_session_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "session_mac_key",
        "kind": "bytes"
      },
      {
        "name": "transaction_input",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Calculate an eight-byte TMV from an already-derived SesTMMACKey and complete transaction input."
  },
  "offline_verify_transaction_mac_aes": {
    "id": 1118,
    "native": "df_offline_verify_transaction_mac_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "transaction_key",
        "kind": "bytes"
      },
      {
        "name": "transaction_counter",
        "kind": "u32"
      },
      {
        "name": "uid",
        "kind": "bytes"
      },
      {
        "name": "transaction_input",
        "kind": "bytes"
      },
      {
        "name": "transaction_mac",
        "kind": "bytes"
      }
    ],
    "output": "boolean",
    "mutation": false,
    "summary": "Verify an eight-byte transaction MAC from the backend key, real UID, committed counter, and exact transaction input."
  },
  "offline_verify_transaction_mac_aes_provider": {
    "id": 1119,
    "native": "df_offline_verify_transaction_mac_aes_provider",
    "surface": "offline",
    "arguments": [
      {
        "name": "provider_source",
        "kind": "key_source"
      },
      {
        "name": "transaction_counter",
        "kind": "u32"
      },
      {
        "name": "uid",
        "kind": "bytes"
      },
      {
        "name": "transaction_input",
        "kind": "bytes"
      },
      {
        "name": "transaction_mac",
        "kind": "bytes"
      }
    ],
    "output": "boolean",
    "mutation": false,
    "summary": "Resolve AppTransactionMACKey before verifying an eight-byte transaction MAC.",
    "providerDirect": "offline_verify_transaction_mac_aes"
  },
  "offline_decrypt_transaction_reader_id_aes": {
    "id": 1120,
    "native": "df_offline_decrypt_transaction_reader_id_aes",
    "surface": "offline",
    "arguments": [
      {
        "name": "session_encryption_key",
        "kind": "bytes"
      },
      {
        "name": "encrypted_reader_id",
        "kind": "bytes"
      }
    ],
    "output": "bytes",
    "mutation": false,
    "summary": "Decrypt one exact 16-byte EncTMRI with an already-derived SesTMENCKey."
  }
});
export const managedOperations = Object.freeze(Object.fromEntries(
    Object.entries(operations).filter(([, value]) => value.surface === 'managed')));
export const rawOperations = Object.freeze(Object.fromEntries(
    Object.entries(operations).filter(([, value]) => value.surface === 'raw')));
export const offlineOperations = Object.freeze(Object.fromEntries(
    Object.entries(operations).filter(([, value]) => value.surface === 'offline')));
