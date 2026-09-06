/** Generated public operation contracts from api/ev3-api.json. */
import type { KeySourceValue } from './keys.js';
export type TimeoutArgument = number | Readonly<{ timeoutMs?: number; signal?: AbortSignal }>;
export interface AuthenticationInfo { readonly transactionIdentifier: Uint8Array; readonly piccCapabilities: Uint8Array; readonly pcdCapabilities: Uint8Array; }
export interface DelegatedApplicationInfo { readonly slotVersion: number; readonly quotaLimit: number; readonly freeBlocks: number; readonly applicationId: number; }
export interface NativeResponse { readonly data: Uint8Array; readonly status: number; }
export interface IsoResponse { readonly data: Uint8Array; readonly status: number; }
export interface PiccConfiguration { readonly disableFormat?: boolean; readonly randomIdentifier?: boolean; readonly proximityCheckMandatory?: boolean; readonly virtualCardAuthenticationMandatory?: boolean; readonly errorCodeBinding?: boolean; readonly randomIdentifierConfiguration?: boolean; readonly fourByteNuidConfiguration?: boolean; }
export interface TransactionOperation { readonly kind: number; readonly file: number; readonly communication: number; readonly offset?: number; readonly record?: number; readonly amount?: number; readonly data?: Uint8Array; }
export interface NativeRequest { readonly framing: number; readonly command: number; readonly data?: Uint8Array; readonly maximumResponse: number; readonly firstFrameDataSize?: number; readonly flags?: number; }
export interface NativeSecureRequest { readonly profile: number; readonly command: number; readonly header?: Uint8Array; readonly data?: Uint8Array; readonly requestCommunication: number; readonly responseCommunication: number; readonly minimumResponse?: number; readonly maximumResponse: number; readonly firstFrameDataSize?: number; readonly flags?: number; readonly invalidatesSession?: boolean; }
export interface IsoApdu { readonly cla: number; readonly ins: number; readonly p1: number; readonly p2: number; readonly data?: Uint8Array; readonly le?: number; readonly lengthEncoding?: number; readonly correctLength?: boolean; readonly maximumResponse: number; readonly maximumFrames: number; }
export interface DelegatedApplicationConfiguration { readonly applicationId: number; readonly keySettings: number; readonly numberOfKeys: number; readonly slot: number; readonly slotVersion: number; readonly quotaLimit: number; readonly isoFileIdentifiers?: boolean; readonly keySettings3?: number; readonly isoId?: number; readonly dfName?: Uint8Array; readonly activeKeySetVersion?: number; readonly numberOfKeySets?: number; readonly maximumKeySize?: number; readonly keySetSettings?: number; }

export interface ManagedOperations {
    /** Read the complete 28-byte native GetVersion payload. */
    get_version(timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Read the available PICC storage in bytes. */
    free_memory(timeout_ms?: TimeoutArgument): Promise<number>;
    /** Select a native application and replace the previous authentication context. */
    select_application(aid: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read one native file number per returned byte. */
    file_ids(timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Establish Standard AES authentication with one borrowed exact key. */
    authenticate_standard_aes(key_number: number, key: Uint8Array, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read application identifiers as consecutive three-byte little-endian values. */
    application_ids(timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Read native GetISOFileIDs output as consecutive two-byte little-endian identifiers. */
    iso_file_ids(timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Read the selected application key-settings payload in native wire order. */
    get_key_settings(timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Read the selected application key-set version payload in native wire order. */
    get_key_set_versions(timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Read the real card UID through the authenticated native command. */
    get_card_uid(timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Read the raw originality signature for separate trusted-key verification. */
    read_originality_signature(timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Abort the card transaction currently pending in the selected application. */
    abort_transaction(timeout_ms?: TimeoutArgument): Promise<void>;
    /** Execute the authenticated PICC format operation and invalidate the session. */
    format_picc(timeout_ms?: TimeoutArgument): Promise<void>;
    /** Delete one file from the selected application. */
    delete_file(file: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read a validated native file-settings payload in wire order. */
    get_file_settings(file: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Stage removal of all records in the selected record file. */
    clear_record_file(file: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read three little-endian SDM counter bytes followed by two reserved bytes. */
    get_file_counters(file: number, communication: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Delete a nonzero native application identifier. */
    delete_application(aid: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Change the selected application key-settings byte. */
    change_key_settings(settings: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read the version payload for one native key and optional key set. */
    get_key_version(number: number, key_set: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Initialize the selected EV3 key set. */
    initialize_key_set(key_set: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Activate the requested EV3 key set and invalidate the old authentication context. */
    roll_key_set(key_set: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Finalize an EV3 key set with its version byte. */
    finalize_key_set(key_set: number, version: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read native data-file bytes using the selected communication mode. */
    read_data(file: number, offset: number, length: number, communication: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Write native data-file bytes; backup-file writes remain pending until commit. */
    write_data(file: number, offset: number, data: Uint8Array, communication: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Stage bytes in a native record file at a byte offset. */
    write_record(file: number, offset: number, data: Uint8Array, communication: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read native record-file content from the specified record index. */
    read_records(file: number, first: number, count: number, communication: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Stage replacement bytes within one native record. */
    update_record(file: number, record: number, offset: number, data: Uint8Array, communication: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Stage an increase to a native value file. */
    credit(file: number, amount: number, communication: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Stage a decrease to a native value file. */
    debit(file: number, amount: number, communication: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Stage a limited-credit increase permitted by the value-file policy. */
    limited_credit(file: number, amount: number, communication: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read the signed value of a native value file. */
    get_value(file: number, communication: number, timeout_ms?: TimeoutArgument): Promise<number>;
    /** Commit staged changes and optionally return the transaction MAC evidence. */
    commit_transaction(return_mac: boolean, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Submit a sixteen-byte ReaderID and return the previous encrypted ReaderID. */
    commit_reader_id(reader_id: Uint8Array, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Create an AES application with optional ISO selection identifiers. */
    create_application(aid: number, key_settings: number, key_count: number, iso_id: number, df_name: Uint8Array, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Create a standard or backup native data file. */
    create_data_file(file: number, length: number, communication: number, access_rights: number, iso_id: number, backup: boolean, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Create a native value file with explicit signed limits and initial value. */
    create_value_file(file: number, lower_limit: number, upper_limit: number, initial_value: number, communication: number, access_rights: number, limited_credit: boolean, free_get_value: boolean, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Create a linear or cyclic native record file. */
    create_record_file(file: number, record_size: number, maximum_records: number, communication: number, access_rights: number, iso_id: number, cyclic: boolean, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Change file communication and access rights under the current command policy. */
    change_file_settings(file: number, communication: number, access_rights: number, command_communication: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Create an AES transaction-MAC file with an explicit backend key. */
    create_transaction_mac_file(file: number, access_rights: number, key: Uint8Array, version: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Replace an AES key using the verified current authentication selector. */
    change_aes_key(number: number, new_key: Uint8Array, version: number, authenticated_key: boolean, old_key: Uint8Array, key_set: number, picc_master: boolean, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Select an ISO file with CLA 00 and optionally return its FCI bytes. */
    iso_select_file(identifier: number, selection: number, response: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Select an ISO DF by name and replace the prior authentication context. */
    iso_select_df_name(name: Uint8Array, response: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Read ISO binary content, checking response CMAC when ISO AES is active. */
    iso_read_binary(short_identifier: number, offset: number, length: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Update ISO binary content using the current ISO authentication state. */
    iso_update_binary(short_identifier: number, offset: number, data: Uint8Array, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Read ISO records, checking response CMAC when ISO AES is active. */
    iso_read_records(record: number, short_identifier: number, selection: number, length: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Append a record with an ISO CLA 00 command. */
    iso_append_record(short_identifier: number, data: Uint8Array, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Read an ISO challenge without establishing a verified SDK session. */
    iso_get_challenge(length: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Send a caller-prepared ISO authentication cryptogram without establishing SDK trust. */
    iso_external_authenticate(number: number, application: boolean, algorithm: number, data: Uint8Array, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Send a caller-prepared ISO challenge without verifying the returned card proof. */
    iso_internal_authenticate(number: number, application: boolean, algorithm: number, data: Uint8Array, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Verify the complete ISO mutual AES proof and establish private response-MAC state. */
    authenticate_iso_aes(number: number, application: boolean, key: Uint8Array, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Resolve exactly one key and establish Standard AES before card I/O. */
    authenticate_standard_aes_provider(key_number: number, provider_source: KeySourceValue, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Establish EV2 First with no PCD capability bytes and return verified metadata. */
    authenticate_ev2_first_aes(key_number: number, key: Uint8Array, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Resolve exactly one key, establish EV2 First, and return verified metadata. */
    authenticate_ev2_first_aes_provider(key_number: number, provider_source: KeySourceValue, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Establish EV2 First with zero through six PCD capability bytes. */
    authenticate_ev2_first_aes_with_capabilities(key_number: number, key: Uint8Array, pcd_capabilities: Uint8Array, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Resolve exactly one key and establish EV2 First with explicit capabilities. */
    authenticate_ev2_first_aes_with_capabilities_provider(key_number: number, provider_source: KeySourceValue, pcd_capabilities: Uint8Array, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Replace an active EV2 session through NonFirst using one exact key. */
    authenticate_ev2_non_first_aes(key_number: number, key: Uint8Array, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Resolve exactly one key and replace an active EV2 session through NonFirst. */
    authenticate_ev2_non_first_aes_provider(key_number: number, provider_source: KeySourceValue, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Resolve exactly one key and establish ISO AES before the first APDU. */
    authenticate_iso_aes_provider(number: number, application: boolean, provider_source: KeySourceValue, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read validated GetDFNames records as AID-LE3, ISO-ID-BE2, length, and name tuples. */
    get_df_names(timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Erase managed authentication locally without performing card I/O. */
    reset_authentication(): Promise<void>;
    /** Stage a MIFARE Classic RestoreTransfer between two checked value files. */
    restore_transfer(target_file: number, source_file: number, communication: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Create one checked delegated AES application with exact issuer authorization bytes. */
    create_delegated_application(aid: number, key_settings: number, number_of_keys: number, slot: number, slot_version: number, quota_limit: number, iso_file_identifiers: boolean, key_settings3: number, iso_id: number, df_name: Uint8Array, encrypted_default_key: Uint8Array, dam_mac: Uint8Array, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read and decode one delegated-application slot. */
    get_delegated_application_info(slot: number, timeout_ms?: TimeoutArgument): Promise<DelegatedApplicationInfo>;
    /** Delete one delegated application using an exact issuer-generated DAM MAC. */
    delete_delegated_application(aid: number, dam_mac: Uint8Array, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Read UID and optional four-byte NUID with one explicit documented request option. */
    get_card_uid_variant(option: number, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Set documented PICC option-zero flags using a versioned descriptor. */
    set_picc_configuration(configuration: PiccConfiguration, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Set the exact nine-byte option-five capability record. */
    set_capability_configuration(capabilities: Uint8Array, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Set the default application AES key and its version. */
    set_default_aes_key(key: Uint8Array, key_version: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Resolve exactly one replacement key and set the default application AES key. */
    set_default_aes_key_provider(provider_source: KeySourceValue, key_version: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Set a complete two-through-twenty-byte ATS including its length byte. */
    set_ats(ats: Uint8Array, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Set the two-byte user ATQA value. */
    set_atqa(atqa: number, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Execute the documented ISO UPDATE RECORD 0xDC or 0xDD variant. */
    iso_update_record(instruction: number, record: number, short_identifier: number, reference_control: number, data: Uint8Array, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Execute one through 128 checked mutations and one explicit commit under one lock. */
    execute_transaction(operations: readonly TransactionOperation[], return_mac: boolean, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Resolve new and optional old AES keys before changing one native key. */
    change_aes_key_provider(number: number, new_key_source: KeySourceValue, version: number, authenticated_key: boolean, old_key_source: KeySourceValue, key_set: number, picc_master: boolean, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Resolve one AES key before creating a transaction-MAC file. */
    create_transaction_mac_file_provider(file: number, access_rights: number, provider_source: KeySourceValue, version: number, timeout_ms?: TimeoutArgument): Promise<void>;
}

export interface RawOperations {
    /** Exchange exactly one native physical frame and preserve its status byte. */
    raw_native_frame(framing: number, command: number, data: Uint8Array, timeout_ms?: TimeoutArgument): Promise<NativeResponse>;
    /** Exchange a bounded native logical command including explicitly requested AF chaining. */
    raw_native_exchange(request: NativeRequest, timeout_ms?: TimeoutArgument): Promise<NativeResponse>;
    /** Exchange one true ISO APDU and preserve the exact final 16-bit status word. */
    raw_iso_exchange(request: IsoApdu, timeout_ms?: TimeoutArgument): Promise<IsoResponse>;
    /** Install a Standard AES session on a native raw channel using one exact key. */
    raw_authenticate_standard_aes(key_number: number, key: Uint8Array, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Resolve exactly one key and install a Standard AES raw session. */
    raw_authenticate_standard_aes_provider(key_number: number, provider_source: KeySourceValue, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Install EV2 First on a native raw channel and return verified public metadata. */
    raw_authenticate_ev2_first_aes(key_number: number, key: Uint8Array, pcd_capabilities: Uint8Array, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Resolve one key and install EV2 First with zero through six capability bytes. */
    raw_authenticate_ev2_first_aes_provider(key_number: number, provider_source: KeySourceValue, pcd_capabilities: Uint8Array, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Replace a raw EV2 session through NonFirst while preserving TI and counter. */
    raw_authenticate_ev2_non_first_aes(key_number: number, key: Uint8Array, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Resolve exactly one key and replace a raw EV2 session through NonFirst. */
    raw_authenticate_ev2_non_first_aes_provider(key_number: number, provider_source: KeySourceValue, timeout_ms?: TimeoutArgument): Promise<AuthenticationInfo>;
    /** Establish a verified ISO mutual AES session on an ISO raw channel. */
    raw_authenticate_iso_aes(key_number: number, application: boolean, key: Uint8Array, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Resolve exactly one key and establish ISO mutual AES on an ISO raw channel. */
    raw_authenticate_iso_aes_provider(key_number: number, application: boolean, provider_source: KeySourceValue, timeout_ms?: TimeoutArgument): Promise<void>;
    /** Execute one explicit secure-native request using its selected active raw session. */
    raw_native_secure_exchange(request: NativeSecureRequest, timeout_ms?: TimeoutArgument): Promise<Uint8Array>;
    /** Execute a checked ISO data command or EF selection through the active raw ISO AES session. */
    raw_iso_secure_exchange(request: IsoApdu, timeout_ms?: TimeoutArgument): Promise<IsoResponse>;
}

export interface OfflineOperations {
    /** Derive one AES-128 key with NXP AN10922 from one through 31 explicit bytes. */
    offline_derive_nxp_aes128(master_key: Uint8Array, diversification: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Resolve one master key and derive AES-128 from the request's diversification bytes. */
    offline_derive_nxp_aes128_provider(provider_source: KeySourceValue, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Calculate an eight-byte AES transaction MAC from explicit counter, UID, and TMI. */
    offline_calculate_transaction_mac_aes(transaction_mac_key: Uint8Array, transaction_counter: number, uid: Uint8Array, transaction_input: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Resolve one transaction key and calculate the eight-byte AES transaction MAC. */
    offline_calculate_transaction_mac_aes_provider(provider_source: KeySourceValue, transaction_counter: number, uid: Uint8Array, transaction_input: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Verify one UID originality signature using a caller-selected supported curve. */
    offline_verify_originality_uid_signature(curve: string, public_key: Uint8Array, uid: Uint8Array, signature: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<boolean>;
    /** Encrypt a delegated application default AES key into the documented 32-byte EncK record. */
    offline_encrypt_delegated_default_key_aes(dam_encryption_key: Uint8Array, application_default_key: Uint8Array, application_default_key_version: number, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Resolve DAMEncKey before encrypting a caller-supplied delegated application default AES key. */
    offline_encrypt_delegated_default_key_aes_provider(provider_source: KeySourceValue, application_default_key: Uint8Array, application_default_key_version: number, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Calculate the eight-byte delegated application creation MAC over one exact versioned configuration and EncK. */
    offline_calculate_delegated_application_mac_aes(dam_mac_key: Uint8Array, configuration: DelegatedApplicationConfiguration, encrypted_default_key: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Resolve DAMMACKey before calculating the delegated application creation MAC. */
    offline_calculate_delegated_application_mac_aes_provider(provider_source: KeySourceValue, configuration: DelegatedApplicationConfiguration, encrypted_default_key: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Calculate the eight-byte issuer MAC authorizing deletion of one delegated application. */
    offline_calculate_delegated_application_delete_mac_aes(dam_mac_key: Uint8Array, application_id: number, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Resolve DAMMACKey before calculating the delegated application deletion MAC. */
    offline_calculate_delegated_application_delete_mac_aes_provider(provider_source: KeySourceValue, application_id: number, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Calculate the eight-byte DAM MAC over explicit old and replacement DF names. */
    offline_calculate_delegated_configuration_mac_aes(dam_mac_key: Uint8Array, old_df_name: Uint8Array, new_df_name: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Resolve DAMMACKey before calculating the delegated DF-name configuration MAC. */
    offline_calculate_delegated_configuration_mac_aes_provider(provider_source: KeySourceValue, old_df_name: Uint8Array, new_df_name: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Calculate the eight-byte AES MAC for one complete MIFARE Classic license and sector-secret record. */
    offline_calculate_mfc_license_mac_aes(license_mac_key: Uint8Array, mfc_license: Uint8Array, mfc_sector_secrets: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Resolve MFCLicenseMACKey before calculating the MIFARE Classic compatibility-license MAC. */
    offline_calculate_mfc_license_mac_aes_provider(provider_source: KeySourceValue, mfc_license: Uint8Array, mfc_sector_secrets: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Derive SesTMMACKey followed by SesTMENCKey into one exact 32-byte result. */
    offline_derive_transaction_mac_keys_aes(transaction_key: Uint8Array, transaction_counter: number, uid: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Resolve AppTransactionMACKey before deriving both transaction session keys. */
    offline_derive_transaction_mac_keys_aes_provider(provider_source: KeySourceValue, transaction_counter: number, uid: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Calculate an eight-byte TMV from an already-derived SesTMMACKey and complete transaction input. */
    offline_calculate_transaction_mac_session_aes(session_mac_key: Uint8Array, transaction_input: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
    /** Verify an eight-byte transaction MAC from the backend key, real UID, committed counter, and exact transaction input. */
    offline_verify_transaction_mac_aes(transaction_key: Uint8Array, transaction_counter: number, uid: Uint8Array, transaction_input: Uint8Array, transaction_mac: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<boolean>;
    /** Resolve AppTransactionMACKey before verifying an eight-byte transaction MAC. */
    offline_verify_transaction_mac_aes_provider(provider_source: KeySourceValue, transaction_counter: number, uid: Uint8Array, transaction_input: Uint8Array, transaction_mac: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<boolean>;
    /** Decrypt one exact 16-byte EncTMRI with an already-derived SesTMENCKey. */
    offline_decrypt_transaction_reader_id_aes(session_encryption_key: Uint8Array, encrypted_reader_id: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
}
