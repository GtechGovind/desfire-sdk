/**
 * @file card.hpp
 * @brief Friendly strong-type C++17 Card facade over the complete raw C ABI owner.
 */
#pragma once

#include <desfire/cpp17/raw.hpp>

namespace desfire::cpp17 {

    /** @brief Verified public EV2 authentication metadata. */
    using AuthenticationInfo = raw::AuthenticationInfo;

    /** @brief Native application creation settings. */
    struct ApplicationConfiguration final {
        ApplicationId application;      /**< Native application identifier to create or select. */
        KeySettings key_settings;       /**< Documented application key-settings byte. */
        std::uint32_t number_of_keys{}; /**< Encoded AES key-count and type byte. */
        std::optional<IsoFileId> iso_file_id; /**< Optional ISO file identifier. */
        Bytes df_name;                        /**< Optional ISO dedicated-file name. */
    };

    /** @brief Standard or backup data-file creation settings. */
    struct DataFileConfiguration final {
        FileNumber file;  /**< Native file number targeted by the configuration. */
        ByteCount length; /**< Requested file length in bytes. */
        CommunicationMode communication{
            CommunicationMode::plain}; /**< File communication policy. */
        AccessRights
            access_rights; /**< Packed read, write, read-write, and change access nibbles. */
        std::optional<IsoFileId> iso_file_id; /**< Optional ISO file identifier. */
        bool backup{}; /**< Whether to create a transactional backup data file. */
    };

    /** @brief Value-file creation settings. */
    struct ValueFileConfiguration final {
        FileNumber file;              /**< Native file number targeted by the configuration. */
        std::int32_t lower_limit{};   /**< Minimum permitted signed value. */
        std::int32_t upper_limit{};   /**< Maximum permitted signed value. */
        std::int32_t initial_value{}; /**< Value installed when the file is created. */
        CommunicationMode communication{
            CommunicationMode::plain}; /**< File communication policy. */
        AccessRights
            access_rights;     /**< Packed read, write, read-write, and change access nibbles. */
        bool limited_credit{}; /**< Whether limited-credit operations are enabled. */
        bool free_get_value{}; /**< Whether reads may occur without authentication. */
    };

    /** @brief Linear or cyclic record-file creation settings. */
    struct RecordFileConfiguration final {
        FileNumber file;           /**< Native file number targeted by the configuration. */
        ByteCount record_size;     /**< Size of each record in bytes. */
        ByteCount maximum_records; /**< Maximum records retained by the file. */
        CommunicationMode communication{
            CommunicationMode::plain}; /**< File communication policy. */
        AccessRights
            access_rights; /**< Packed read, write, read-write, and change access nibbles. */
        std::optional<IsoFileId> iso_file_id; /**< Optional ISO file identifier. */
        bool cyclic{}; /**< Whether the record file overwrites its oldest record when full. */
    };

    /** @brief Explicit current-session inputs for one AES key replacement. */
    struct ChangeAesKeyConfiguration final {
        KeyNumber key;      /**< Native key number to replace. */
        KeyVersion version; /**< Version byte assigned to the replacement key. */
        KeyNumber
            authenticated_key; /**< Native key number used for the current authenticated session. */
        std::optional<KeySetNumber> key_set; /**< Optional EV3 key-set scope. */
        bool picc_master{};                  /**< Whether PICC master-key encoding is required. */
    };

    /** @brief Named PICC configuration flags accepted by option zero. */
    struct PiccConfiguration final {
        bool disable_format{};            /**< Whether PICC formatting is disabled. */
        bool random_identifier{};         /**< Whether random card identifiers are enabled. */
        bool proximity_check_mandatory{}; /**< Whether proximity checking is mandatory. */
        bool virtual_card_authentication_mandatory{}; /**< Whether virtual-card authentication is
                                                         mandatory. */
        bool error_code_binding{}; /**< Whether secure error-code binding is enabled. */
        bool random_identifier_configuration{}; /**< Whether random-identifier configuration is
                                                   enabled. */
        bool four_byte_nuid_configuration{};    /**< Whether four-byte NUID output is enabled. */
    };

    /**
     * @brief Managed C++17 Card with RAII ownership, strong identifiers, and Result returns.
     *
     * One Card owns one activated transport context through the C ABI. Operations are serialized
     * by the native library; cancel() remains callable concurrently. Unknown mutation delivery is
     * preserved in Error::outcome and must be reconciled instead of blindly retried.
     */
    class Card final {
    public:

        /**
         * @brief Open a managed Card without card I/O.
         * @param transport Versioned transport whose callback context follows its retain contract.
         * @return Owning Card or validation failure.
         */
        static Result<Card> open(const df_transport_v1& transport) {
            auto opened = raw::Card::open(transport);
            if (!opened) {
                return Result<Card>::failure(std::move(opened).error());
            }
            return Result<Card>::success(Card(std::move(opened).value()));
        }

        /** @brief Destruction performs a best-effort native close and never resets the card. */
        ~Card() = default;

        /** @brief Prevent duplicate ownership of one native handle. */
        Card(const Card&) = delete;

        /** @brief Prevent duplicate ownership of one native handle. */
        Card& operator=(const Card&) = delete;

        /** @brief Transfer the only native owner. */
        Card(Card&&) noexcept = default;

        /** @brief Prevent abandoning a live destination handle during move assignment. */
        Card& operator=(Card&&) = delete;

        /**
         * @brief Expose the exact result-based C ABI layer for advanced operations.
         * @return Mutable reference to the raw facade owned by this Card.
         */
        raw::Card& raw_card() noexcept {
            return raw_;
        }

        /**
         * @brief Expose the immutable exact result-based C ABI layer.
         * @return Immutable reference to the raw facade owned by this Card.
         */
        const raw::Card& raw_card() const noexcept {
            return raw_;
        }

        /**
         * @brief Explicitly close; a busy failure leaves the Card owning its handle.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> close() {
            return raw_.close();
        }

        /**
         * @brief Reset the transport and erase all managed authentication state.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> reset() {
            return raw_.reset();
        }

        /**
         * @brief Request cancellation without waiting for the active operation lock.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> cancel() {
            return raw_.cancel();
        }

        /**
         * @brief Invalidate managed state after external removal, reset, or reconnection.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> notify_state_change() {
            return raw_.notify_state_change();
        }

        /**
         * @brief Erase local authentication state without card I/O.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> reset_authentication() {
            return raw_.reset_authentication();
        }

        /**
         * @brief Read the complete version payload.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> get_version(std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout,
                                [&](std::uint32_t value) { return raw_.get_version(value); });
        }

        /**
         * @brief Read available PICC storage in bytes.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<std::uint32_t> free_memory(std::chrono::milliseconds timeout = default_timeout) {
            return timed<std::uint32_t>(
                timeout, [&](std::uint32_t value) { return raw_.free_memory(value); });
        }

        /**
         * @brief Select a native application and replace authentication state.
         * @param application Native application identifier to select.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> select_application(ApplicationId application,
                                        std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.select_application(application.value(), value);
            });
        }

        /**
         * @brief Read native file numbers in wire order.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> file_ids(std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) { return raw_.file_ids(value); });
        }

        /**
         * @brief Read native application identifiers as three-byte little-endian tuples.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> application_ids(std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout,
                                [&](std::uint32_t value) { return raw_.application_ids(value); });
        }

        /**
         * @brief Read validated DF-name tuples in their documented binary encoding.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> df_names(std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout,
                                [&](std::uint32_t value) { return raw_.get_df_names(value); });
        }

        /**
         * @brief Read ISO file identifiers as two-byte little-endian tuples.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> iso_file_ids(std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout,
                                [&](std::uint32_t value) { return raw_.iso_file_ids(value); });
        }

        /**
         * @brief Establish Standard AES using a live direct key borrowed until return.
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void>
        authenticate_standard_aes(KeyNumber key_number, const Aes128Key& key,
                                  std::chrono::milliseconds timeout = default_timeout) {
            auto checked = validate_direct_authentication(key_number, key);
            if (!checked) {
                return checked;
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.authenticate_standard_aes(key_number.value(), key.data(), key.size(),
                                                      value);
            });
        }

        /**
         * @brief Derive exactly once and establish Standard AES before the first card frame.
         * @param master_key Live AES-128 master key borrowed only for derivation.
         * @param deriver Synchronous application-defined derivation implementation.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void>
        authenticate_standard_aes(const Aes128Key& master_key, Aes128KeyDeriver& deriver,
                                  const Aes128DerivationContext& context,
                                  std::chrono::milliseconds timeout = default_timeout) {
            auto key = derive_authentication_key(master_key, deriver, context);
            if (!key) {
                return Result<void>::failure(std::move(key).error());
            }
            return authenticate_standard_aes(context.key_number, key.value(), timeout);
        }

        /**
         * @brief Resolve exactly once and establish Standard AES before the first card frame.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void>
        authenticate_standard_aes(Aes128KeyProvider& provider, const KeyRequest& request,
                                  std::chrono::milliseconds timeout = default_timeout) {
            auto checked = validate_provider_authentication(
                request, AuthenticationProfile::standard_aes, false);
            if (!checked) {
                return checked;
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                detail::ProviderCall call(provider, request);
                return raw_.authenticate_standard_aes_provider(
                    request.context.key_number.value(), call.provider(), call.request(), value);
            });
        }

        /**
         * @brief Establish EV2 First using a live direct key and empty PCD capabilities.
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo>
        authenticate_ev2_first_aes(KeyNumber key_number, const Aes128Key& key,
                                   std::chrono::milliseconds timeout = default_timeout) {
            auto checked = validate_direct_authentication(key_number, key);
            if (!checked) {
                return Result<AuthenticationInfo>::failure(std::move(checked).error());
            }
            return timed<AuthenticationInfo>(timeout, [&](std::uint32_t value) {
                return raw_.authenticate_ev2_first_aes(key_number.value(), key.data(), key.size(),
                                                       value);
            });
        }

        /**
         * @brief Derive exactly once and establish EV2 First with empty PCD capabilities.
         * @param master_key Live AES-128 master key borrowed only for derivation.
         * @param deriver Synchronous application-defined derivation implementation.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo>
        authenticate_ev2_first_aes(const Aes128Key& master_key, Aes128KeyDeriver& deriver,
                                   const Aes128DerivationContext& context,
                                   std::chrono::milliseconds timeout = default_timeout) {
            auto key = derive_authentication_key(master_key, deriver, context);
            if (!key) {
                return Result<AuthenticationInfo>::failure(std::move(key).error());
            }
            return authenticate_ev2_first_aes(context.key_number, key.value(), timeout);
        }

        /**
         * @brief Resolve exactly once and establish EV2 First with empty PCD capabilities.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo>
        authenticate_ev2_first_aes(Aes128KeyProvider& provider, const KeyRequest& request,
                                   std::chrono::milliseconds timeout = default_timeout) {
            auto checked =
                validate_provider_authentication(request, AuthenticationProfile::ev2_first, false);
            if (!checked) {
                return Result<AuthenticationInfo>::failure(std::move(checked).error());
            }
            return timed<AuthenticationInfo>(timeout, [&](std::uint32_t value) {
                detail::ProviderCall call(provider, request);
                return raw_.authenticate_ev2_first_aes_provider(
                    request.context.key_number.value(), call.provider(), call.request(), value);
            });
        }

        /**
         * @brief Establish EV2 First with zero through six explicit PCD capability bytes.
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param pcd_capabilities Zero through six explicit reader capability bytes.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo> authenticate_ev2_first_aes_with_capabilities(
            KeyNumber key_number, const Aes128Key& key, const Bytes& pcd_capabilities,
            std::chrono::milliseconds timeout = default_timeout) {
            auto checked = validate_direct_authentication(key_number, key);
            if (!checked) {
                return Result<AuthenticationInfo>::failure(std::move(checked).error());
            }
            if (pcd_capabilities.size() > 6) {
                return Result<AuthenticationInfo>::failure(
                    detail::invalid_argument("PCD capabilities may contain at most six bytes"));
            }
            return timed<AuthenticationInfo>(timeout, [&](std::uint32_t value) {
                return raw_.authenticate_ev2_first_aes_with_capabilities(
                    key_number.value(), key.data(), key.size(), detail::byte_data(pcd_capabilities),
                    pcd_capabilities.size(), value);
            });
        }

        /**
         * @brief Derive exactly once and establish EV2 First with explicit capabilities.
         * @param master_key Live AES-128 master key borrowed only for derivation.
         * @param deriver Synchronous application-defined derivation implementation.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @param pcd_capabilities Zero through six explicit reader capability bytes.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo> authenticate_ev2_first_aes_with_capabilities(
            const Aes128Key& master_key, Aes128KeyDeriver& deriver,
            const Aes128DerivationContext& context, const Bytes& pcd_capabilities,
            std::chrono::milliseconds timeout = default_timeout) {
            if (pcd_capabilities.size() > 6) {
                return Result<AuthenticationInfo>::failure(
                    detail::invalid_argument("PCD capabilities may contain at most six bytes"));
            }
            auto key = derive_authentication_key(master_key, deriver, context);
            if (!key) {
                return Result<AuthenticationInfo>::failure(std::move(key).error());
            }
            return authenticate_ev2_first_aes_with_capabilities(context.key_number, key.value(),
                                                                pcd_capabilities, timeout);
        }

        /**
         * @brief Resolve exactly once and establish EV2 First with explicit capabilities.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param pcd_capabilities Zero through six explicit reader capability bytes.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo> authenticate_ev2_first_aes_with_capabilities(
            Aes128KeyProvider& provider, const KeyRequest& request, const Bytes& pcd_capabilities,
            std::chrono::milliseconds timeout = default_timeout) {
            auto checked =
                validate_provider_authentication(request, AuthenticationProfile::ev2_first, false);
            if (!checked) {
                return Result<AuthenticationInfo>::failure(std::move(checked).error());
            }
            if (pcd_capabilities.size() > 6) {
                return Result<AuthenticationInfo>::failure(
                    detail::invalid_argument("PCD capabilities may contain at most six bytes"));
            }
            return timed<AuthenticationInfo>(timeout, [&](std::uint32_t value) {
                detail::ProviderCall call(provider, request);
                return raw_.authenticate_ev2_first_aes_with_capabilities_provider(
                    request.context.key_number.value(), call.provider(), call.request(),
                    detail::byte_data(pcd_capabilities), pcd_capabilities.size(), value);
            });
        }

        /**
         * @brief Establish EV2 NonFirst using a live direct key.
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo>
        authenticate_ev2_non_first_aes(KeyNumber key_number, const Aes128Key& key,
                                       std::chrono::milliseconds timeout = default_timeout) {
            auto checked = validate_direct_authentication(key_number, key);
            if (!checked) {
                return Result<AuthenticationInfo>::failure(std::move(checked).error());
            }
            return timed<AuthenticationInfo>(timeout, [&](std::uint32_t value) {
                return raw_.authenticate_ev2_non_first_aes(key_number.value(), key.data(),
                                                           key.size(), value);
            });
        }

        /**
         * @brief Derive exactly once and establish EV2 NonFirst before its first card frame.
         * @param master_key Live AES-128 master key borrowed only for derivation.
         * @param deriver Synchronous application-defined derivation implementation.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo>
        authenticate_ev2_non_first_aes(const Aes128Key& master_key, Aes128KeyDeriver& deriver,
                                       const Aes128DerivationContext& context,
                                       std::chrono::milliseconds timeout = default_timeout) {
            auto key = derive_authentication_key(master_key, deriver, context);
            if (!key) {
                return Result<AuthenticationInfo>::failure(std::move(key).error());
            }
            return authenticate_ev2_non_first_aes(context.key_number, key.value(), timeout);
        }

        /**
         * @brief Resolve exactly once and establish EV2 NonFirst before its first card frame.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo>
        authenticate_ev2_non_first_aes(Aes128KeyProvider& provider, const KeyRequest& request,
                                       std::chrono::milliseconds timeout = default_timeout) {
            auto checked = validate_provider_authentication(
                request, AuthenticationProfile::ev2_non_first, false);
            if (!checked) {
                return Result<AuthenticationInfo>::failure(std::move(checked).error());
            }
            return timed<AuthenticationInfo>(timeout, [&](std::uint32_t value) {
                detail::ProviderCall call(provider, request);
                return raw_.authenticate_ev2_non_first_aes_provider(
                    request.context.key_number.value(), call.provider(), call.request(), value);
            });
        }

        /**
         * @brief Establish verified ISO mutual AES with one direct key.
         * @param key_number Validated native key selector.
         * @param application_key True for application-key scope; false for the PICC master key.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> authenticate_iso_aes(KeyNumber key_number, bool application_key,
                                          const Aes128Key& key,
                                          std::chrono::milliseconds timeout = default_timeout) {
            if (!key.valid()) {
                return Result<void>::failure(
                    detail::invalid_argument("AES-128 key ownership is empty"));
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.authenticate_iso_aes(key_number.value(), application_key ? 1U : 0U,
                                                 key.data(), key.size(), value);
            });
        }

        /**
         * @brief Derive exactly once and establish ISO AES before the first APDU.
         * @param application_key True for application-key scope; false for the PICC master key.
         * @param master_key Live AES-128 master key borrowed only for derivation.
         * @param deriver Synchronous application-defined derivation implementation.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> authenticate_iso_aes(bool application_key, const Aes128Key& master_key,
                                          Aes128KeyDeriver& deriver,
                                          const Aes128DerivationContext& context,
                                          std::chrono::milliseconds timeout = default_timeout) {
            auto key = derive_authentication_key(master_key, deriver, context);
            if (!key) {
                return Result<void>::failure(std::move(key).error());
            }
            return authenticate_iso_aes(context.key_number, application_key, key.value(), timeout);
        }

        /**
         * @brief Resolve exactly once and establish ISO AES before the first APDU.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> authenticate_iso_aes(Aes128KeyProvider& provider, const KeyRequest& request,
                                          std::chrono::milliseconds timeout = default_timeout) {
            auto checked =
                validate_provider_authentication(request, AuthenticationProfile::iso_aes, true);
            if (!checked) {
                return checked;
            }
            const bool application_key = request.scope == KeyScope::iso_application;
            return timed<void>(timeout, [&](std::uint32_t value) {
                detail::ProviderCall call(provider, request);
                return raw_.authenticate_iso_aes_provider(request.context.key_number.value(),
                                                          application_key ? 1U : 0U,
                                                          call.provider(), call.request(), value);
            });
        }

        /**
         * @brief Read selected-application key settings in checked wire order.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> get_key_settings(std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout,
                                [&](std::uint32_t value) { return raw_.get_key_settings(value); });
        }

        /**
         * @brief Read key-set versions in checked wire order.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> get_key_set_versions(std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(
                timeout, [&](std::uint32_t value) { return raw_.get_key_set_versions(value); });
        }

        /**
         * @brief Read one key version with an optional EV3 key set.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> get_key_version(KeyNumber key, std::optional<KeySetNumber> key_set = {},
                                      std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.get_key_version(key.value(), optional_key_set(key_set), value);
            });
        }

        /**
         * @brief Change the selected application key-settings byte.
         * @param settings Packed application key-settings byte to write.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> change_key_settings(KeySettings settings,
                                         std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.change_key_settings(settings.value(), value);
            });
        }

        /**
         * @brief Initialize one EV3 key set.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> initialize_key_set(KeySetNumber key_set,
                                        std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.initialize_key_set(key_set.value(), value);
            });
        }

        /**
         * @brief Activate one EV3 key set and invalidate old authentication.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> roll_key_set(KeySetNumber key_set,
                                  std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.roll_key_set(key_set.value(), value);
            });
        }

        /**
         * @brief Finalize one EV3 key set with an explicit version.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param version Key version encoded by the command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> finalize_key_set(KeySetNumber key_set, KeyVersion version,
                                      std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.finalize_key_set(key_set.value(), version.value(), value);
            });
        }

        /**
         * @brief Create one checked native application.
         * @param configuration Named configuration whose fields are encoded by the matching
         * command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> create_application(const ApplicationConfiguration& configuration,
                                        std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.create_application(
                    configuration.application.value(), configuration.key_settings.value(),
                    configuration.number_of_keys, optional_iso_id(configuration.iso_file_id),
                    detail::byte_data(configuration.df_name), configuration.df_name.size(), value);
            });
        }

        /**
         * @brief Delete one non-PICC native application.
         * @param application Nonzero selects application-key scope; zero selects PICC master-key
         * scope.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> delete_application(ApplicationId application,
                                        std::chrono::milliseconds timeout = default_timeout) {
            if (application.value() == 0) {
                return Result<void>::failure(
                    detail::invalid_argument("the PICC application cannot be deleted"));
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.delete_application(application.value(), value);
            });
        }

        /**
         * @brief Delete one native file.
         * @param file Native file number targeted by the command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> delete_file(FileNumber file,
                                 std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.delete_file(file.value(), value);
            });
        }

        /**
         * @brief Read validated file settings in their documented binary encoding.
         * @param file Native file number targeted by the command.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> get_file_settings(FileNumber file,
                                        std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.get_file_settings(file.value(), value);
            });
        }

        /**
         * @brief Read SDM file counters using the declared file communication mode.
         * @param file Native file number targeted by the command.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> get_file_counters(FileNumber file, CommunicationMode communication,
                                        std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.get_file_counters(file.value(), scalar(communication), value);
            });
        }

        /**
         * @brief Read native data bytes.
         * @param file Native file number targeted by the command.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param length Requested byte count; zero retains the command-specific remaining-data
         * meaning.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> read_data(FileNumber file, Offset offset, ByteCount length,
                                CommunicationMode communication,
                                std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.read_data(file.value(), offset.value(), length.value(),
                                      scalar(communication), value);
            });
        }

        /**
         * @brief Write native data; backup writes remain staged until commit.
         * @param file Native file number targeted by the command.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> write_data(FileNumber file, Offset offset, const Bytes& data,
                                CommunicationMode communication,
                                std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.write_data(file.value(), offset.value(), detail::byte_data(data),
                                       data.size(), scalar(communication), value);
            });
        }

        /**
         * @brief Read native records.
         * @param file Native file number targeted by the command.
         * @param first Zero-based index of the first native record to return.
         * @param count Maximum number of native records to return.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> read_records(FileNumber file, Offset first, ByteCount count,
                                   CommunicationMode communication,
                                   std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.read_records(file.value(), first.value(), count.value(),
                                         scalar(communication), value);
            });
        }

        /**
         * @brief Append or partially write native record data.
         * @param file Native file number targeted by the command.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> write_record(FileNumber file, Offset offset, const Bytes& data,
                                  CommunicationMode communication,
                                  std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.write_record(file.value(), offset.value(), detail::byte_data(data),
                                         data.size(), scalar(communication), value);
            });
        }

        /**
         * @brief Update one native record range.
         * @param file Native file number targeted by the command.
         * @param record Record number selected by the native or ISO command.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> update_record(FileNumber file, Offset record, Offset offset, const Bytes& data,
                                   CommunicationMode communication,
                                   std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.update_record(file.value(), record.value(), offset.value(),
                                          detail::byte_data(data), data.size(),
                                          scalar(communication), value);
            });
        }

        /**
         * @brief Stage clearing all records in one record file.
         * @param file Native file number targeted by the command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> clear_record_file(FileNumber file,
                                       std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.clear_record_file(file.value(), value);
            });
        }

        /**
         * @brief Read one value-file balance.
         * @param file Native file number targeted by the command.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<std::int32_t> get_value(FileNumber file, CommunicationMode communication,
                                       std::chrono::milliseconds timeout = default_timeout) {
            return timed<std::int32_t>(timeout, [&](std::uint32_t value) {
                return raw_.get_value(file.value(), scalar(communication), value);
            });
        }

        /**
         * @brief Stage one unsigned value-file credit.
         * @param file Native file number targeted by the command.
         * @param amount Unsigned value adjustment encoded by the credit or debit command.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> credit(FileNumber file, std::uint32_t amount, CommunicationMode communication,
                            std::chrono::milliseconds timeout = default_timeout) {
            return value_mutation(&raw::Card::credit, file, amount, communication, timeout);
        }

        /**
         * @brief Stage one unsigned value-file debit.
         * @param file Native file number targeted by the command.
         * @param amount Unsigned value adjustment encoded by the credit or debit command.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> debit(FileNumber file, std::uint32_t amount, CommunicationMode communication,
                           std::chrono::milliseconds timeout = default_timeout) {
            return value_mutation(&raw::Card::debit, file, amount, communication, timeout);
        }

        /**
         * @brief Stage one unsigned limited credit.
         * @param file Native file number targeted by the command.
         * @param amount Unsigned value adjustment encoded by the credit or debit command.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> limited_credit(FileNumber file, std::uint32_t amount,
                                    CommunicationMode communication,
                                    std::chrono::milliseconds timeout = default_timeout) {
            return value_mutation(&raw::Card::limited_credit, file, amount, communication, timeout);
        }

        /**
         * @brief Commit the active transaction and optionally return its transaction MAC.
         * @param return_mac True to request transaction-MAC evidence from the commit.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> commit_transaction(bool return_mac,
                                         std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.commit_transaction(return_mac ? 1U : 0U, value);
            });
        }

        /**
         * @brief Abort the transaction currently pending in the selected application.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> abort_transaction(std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout,
                               [&](std::uint32_t value) { return raw_.abort_transaction(value); });
        }

        /**
         * @brief Commit and authenticate one exact sixteen-byte reader identifier.
         * @param reader_id Exact ReaderID bytes committed with the current transaction.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> commit_reader_id(const Bytes& reader_id,
                                       std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.commit_reader_id(detail::byte_data(reader_id), reader_id.size(), value);
            });
        }

        /**
         * @brief Stage restore-transfer between two checked value files.
         * @param target Destination value file for RestoreTransfer.
         * @param source Native source value-file number for RestoreTransfer.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> restore_transfer(FileNumber target, FileNumber source,
                                      CommunicationMode communication,
                                      std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.restore_transfer(target.value(), source.value(), scalar(communication),
                                             value);
            });
        }

        /**
         * @brief Create a standard or backup native data file.
         * @param configuration Named configuration whose fields are encoded by the matching
         * command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> create_data_file(const DataFileConfiguration& configuration,
                                      std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.create_data_file(
                    configuration.file.value(), configuration.length.value(),
                    scalar(configuration.communication), configuration.access_rights.value(),
                    optional_iso_id(configuration.iso_file_id), configuration.backup ? 1U : 0U,
                    value);
            });
        }

        /**
         * @brief Create one native value file.
         * @param configuration Named configuration whose fields are encoded by the matching
         * command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> create_value_file(const ValueFileConfiguration& configuration,
                                       std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.create_value_file(
                    configuration.file.value(), configuration.lower_limit,
                    configuration.upper_limit, configuration.initial_value,
                    scalar(configuration.communication), configuration.access_rights.value(),
                    configuration.limited_credit ? 1U : 0U, configuration.free_get_value ? 1U : 0U,
                    value);
            });
        }

        /**
         * @brief Create one linear or cyclic native record file.
         * @param configuration Named configuration whose fields are encoded by the matching
         * command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> create_record_file(const RecordFileConfiguration& configuration,
                                        std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.create_record_file(
                    configuration.file.value(), configuration.record_size.value(),
                    configuration.maximum_records.value(), scalar(configuration.communication),
                    configuration.access_rights.value(), optional_iso_id(configuration.iso_file_id),
                    configuration.cyclic ? 1U : 0U, value);
            });
        }

        /**
         * @brief Change file protection and access rights under an explicit command mode.
         * @param file Native file number targeted by the command.
         * @param communication Communication mode required by the target file.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param command_communication Secure messaging mode used to protect ChangeFileSettings
         * itself.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> change_file_settings(FileNumber file, CommunicationMode communication,
                                          AccessRights access_rights,
                                          CommunicationMode command_communication,
                                          std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.change_file_settings(file.value(), scalar(communication),
                                                 access_rights.value(),
                                                 scalar(command_communication), value);
            });
        }

        /**
         * @brief Create a transaction-MAC file with one direct AES key.
         * @param file Native file number targeted by the command.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param version Key version encoded by the command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void>
        create_transaction_mac_file(FileNumber file, AccessRights access_rights,
                                    const Aes128Key& key, KeyVersion version,
                                    std::chrono::milliseconds timeout = default_timeout) {
            if (!key.valid()) {
                return Result<void>::failure(
                    detail::invalid_argument("AES-128 key ownership is empty"));
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.create_transaction_mac_file(file.value(), access_rights.value(),
                                                        key.data(), key.size(), version.value(),
                                                        value);
            });
        }

        /**
         * @brief Derive exactly once before creating a transaction-MAC file.
         * @param file Native file number targeted by the command.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param master_key Live AES-128 master key borrowed only for derivation.
         * @param deriver Synchronous application-defined derivation implementation.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @param version Key version encoded by the command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void>
        create_transaction_mac_file(FileNumber file, AccessRights access_rights,
                                    const Aes128Key& master_key, Aes128KeyDeriver& deriver,
                                    const Aes128DerivationContext& context, KeyVersion version,
                                    std::chrono::milliseconds timeout = default_timeout) {
            auto key = derive_key(master_key, deriver, context, KeyPurpose::transaction_mac);
            if (!key) {
                return Result<void>::failure(std::move(key).error());
            }
            return create_transaction_mac_file(file, access_rights, key.value(), version, timeout);
        }

        /**
         * @brief Resolve exactly once before creating a transaction-MAC file.
         * @param file Native file number targeted by the command.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param version Key version encoded by the command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void>
        create_transaction_mac_file(FileNumber file, AccessRights access_rights,
                                    Aes128KeyProvider& provider, const KeyRequest& request,
                                    KeyVersion version,
                                    std::chrono::milliseconds timeout = default_timeout) {
            auto checked = validate_provider_request(request, KeyPurpose::transaction_mac);
            if (!checked) {
                return checked;
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                detail::ProviderCall call(provider, request);
                return raw_.create_transaction_mac_file_provider(
                    file.value(), access_rights.value(), call.provider(), call.request(),
                    version.value(), value);
            });
        }

        /**
         * @brief Replace one AES key using direct replacement and optional old-key material.
         * @param configuration Named configuration whose fields are encoded by the matching
         * command.
         * @param replacement Live replacement AES key borrowed through the ChangeKey call.
         * @param old_key Optional current AES-128 key bytes borrowed until return.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> change_aes_key(const ChangeAesKeyConfiguration& configuration,
                                    const Aes128Key& replacement,
                                    const Aes128Key* old_key = nullptr,
                                    std::chrono::milliseconds timeout = default_timeout) {
            if (!replacement.valid() || (old_key != nullptr && !old_key->valid())) {
                return Result<void>::failure(
                    detail::invalid_argument("AES-128 key ownership is empty"));
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.change_aes_key(configuration.key.value(), replacement.data(),
                                           replacement.size(), configuration.version.value(),
                                           configuration.authenticated_key.value(),
                                           old_key == nullptr ? nullptr : old_key->data(),
                                           old_key == nullptr ? 0 : old_key->size(),
                                           optional_key_set(configuration.key_set),
                                           configuration.picc_master ? 1U : 0U, value);
            });
        }

        /**
         * @brief Resolve replacement and optional old keys once each before changing one AES key.
         * @param configuration Checked key selectors, version, set, and PICC/application scope.
         * @param replacement_provider Provider for a replacement_key request.
         * @param replacement_request Non-secret replacement-key request.
         * @param old_provider Optional provider for a current_key request.
         * @param old_request Optional request paired with old_provider.
         * @param timeout Complete resolution and command timeout.
         * @return Success or exact pre-I/O/card failure evidence.
         */
        Result<void> change_aes_key(const ChangeAesKeyConfiguration& configuration,
                                    Aes128KeyProvider& replacement_provider,
                                    const KeyRequest& replacement_request,
                                    Aes128KeyProvider* old_provider = nullptr,
                                    const KeyRequest* old_request = nullptr,
                                    std::chrono::milliseconds timeout = default_timeout) {
            auto replacement_checked =
                validate_provider_request(replacement_request, KeyPurpose::replacement_key);
            if (!replacement_checked) {
                return replacement_checked;
            }
            if ((old_provider == nullptr) != (old_request == nullptr)) {
                return Result<void>::failure(detail::invalid_argument(
                    "old key provider and request must either both be present or both be absent"));
            }
            if (old_request != nullptr) {
                auto old_checked = validate_provider_request(*old_request, KeyPurpose::current_key);
                if (!old_checked) {
                    return old_checked;
                }
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                detail::ProviderCall replacement_call(replacement_provider, replacement_request);
                if (old_provider == nullptr) {
                    return raw_.change_aes_key_provider(
                        configuration.key.value(), replacement_call.provider(),
                        replacement_call.request(), configuration.version.value(),
                        configuration.authenticated_key.value(), nullptr, nullptr,
                        optional_key_set(configuration.key_set),
                        configuration.picc_master ? 1U : 0U, value);
                }
                detail::ProviderCall old_call(*old_provider, *old_request);
                return raw_.change_aes_key_provider(
                    configuration.key.value(), replacement_call.provider(),
                    replacement_call.request(), configuration.version.value(),
                    configuration.authenticated_key.value(), old_call.provider(),
                    old_call.request(), optional_key_set(configuration.key_set),
                    configuration.picc_master ? 1U : 0U, value);
            });
        }

        /**
         * @brief Read the authenticated real UID.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> get_card_uid(std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout,
                                [&](std::uint32_t value) { return raw_.get_card_uid(value); });
        }

        /**
         * @brief Read UID and optionally NUID with the explicit C ABI option.
         * @param option Documented UID/NUID response selector.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> get_card_uid_variant(std::uint32_t option,
                                           std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.get_card_uid_variant(option, value);
            });
        }

        /**
         * @brief Read the raw originality signature for separate trusted-key verification.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes>
        read_originality_signature(std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.read_originality_signature(value);
            });
        }

        /**
         * @brief Format the PICC under the active authenticated policy.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> format_picc(std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout,
                               [&](std::uint32_t value) { return raw_.format_picc(value); });
        }

        /**
         * @brief Set the documented option-zero PICC flags.
         * @param configuration Named configuration whose fields are encoded by the matching
         * command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_picc_configuration(const PiccConfiguration& configuration,
                                            std::chrono::milliseconds timeout = default_timeout) {
            df_picc_configuration_v1 native{};
            native.struct_size = sizeof(native);
            native.abi_version = DF_ABI_VERSION;
            native.disable_format = configuration.disable_format ? 1U : 0U;
            native.random_identifier = configuration.random_identifier ? 1U : 0U;
            native.proximity_check_mandatory = configuration.proximity_check_mandatory ? 1U : 0U;
            native.virtual_card_authentication_mandatory =
                configuration.virtual_card_authentication_mandatory ? 1U : 0U;
            native.error_code_binding = configuration.error_code_binding ? 1U : 0U;
            native.random_identifier_configuration =
                configuration.random_identifier_configuration ? 1U : 0U;
            native.four_byte_nuid_configuration =
                configuration.four_byte_nuid_configuration ? 1U : 0U;
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.set_picc_configuration(&native, value);
            });
        }

        /**
         * @brief Set the exact nine-byte PICC capability record.
         * @param capabilities Exact nine-byte PICC capability configuration record.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void>
        set_capability_configuration(const Bytes& capabilities,
                                     std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.set_capability_configuration(detail::byte_data(capabilities),
                                                         capabilities.size(), value);
            });
        }

        /**
         * @brief Set the default application AES key and version.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param version Key version encoded by the command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_default_aes_key(const Aes128Key& key, KeyVersion version,
                                         std::chrono::milliseconds timeout = default_timeout) {
            if (!key.valid()) {
                return Result<void>::failure(
                    detail::invalid_argument("AES-128 key ownership is empty"));
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.set_default_aes_key(key.data(), key.size(), version.value(), value);
            });
        }

        /**
         * @brief Derive exactly once before setting the default application AES key.
         * @param master_key Live AES-128 master key borrowed only for derivation.
         * @param deriver Synchronous application-defined derivation implementation.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @param version Key version encoded by the command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_default_aes_key(const Aes128Key& master_key, Aes128KeyDeriver& deriver,
                                         const Aes128DerivationContext& context, KeyVersion version,
                                         std::chrono::milliseconds timeout = default_timeout) {
            auto key = derive_key(master_key, deriver, context, KeyPurpose::replacement_key);
            if (!key) {
                return Result<void>::failure(std::move(key).error());
            }
            return set_default_aes_key(key.value(), version, timeout);
        }

        /**
         * @brief Resolve exactly once before setting the default application AES key.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param version Key version encoded by the command.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_default_aes_key(Aes128KeyProvider& provider, const KeyRequest& request,
                                         KeyVersion version,
                                         std::chrono::milliseconds timeout = default_timeout) {
            auto checked = validate_provider_request(request, KeyPurpose::replacement_key);
            if (!checked) {
                return checked;
            }
            return timed<void>(timeout, [&](std::uint32_t value) {
                detail::ProviderCall call(provider, request);
                return raw_.set_default_aes_key_provider(call.provider(), call.request(),
                                                         version.value(), value);
            });
        }

        /**
         * @brief Set a complete ATS including its length byte.
         * @param ats Complete ATS bytes, including the encoded length byte.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_ats(const Bytes& ats,
                             std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return raw_.set_ats(detail::byte_data(ats), ats.size(), value);
            });
        }

        /**
         * @brief Set the two-byte user ATQA value.
         * @param atqa Two-byte user ATQA value widened to an unsigned integer.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_atqa(std::uint16_t atqa,
                              std::chrono::milliseconds timeout = default_timeout) {
            return timed<void>(timeout,
                               [&](std::uint32_t value) { return raw_.set_atqa(atqa, value); });
        }

        /**
         * @brief Select an ISO file with explicit selection and response-control bytes.
         * @param identifier ISO file identifier used for selection.
         * @param selection ISO P2 file-selection control byte.
         * @param response Native response descriptor populated by the C ABI.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> iso_select_file(IsoFileId identifier, std::uint32_t selection,
                                      std::uint32_t response,
                                      std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.iso_select_file(identifier.value(), selection, response, value);
            });
        }

        /**
         * @brief Select an ISO DF name with explicit response control.
         * @param name Borrowed ISO dedicated-file name bytes.
         * @param response Native response descriptor populated by the C ABI.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> iso_select_df_name(const Bytes& name, std::uint32_t response,
                                         std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.iso_select_df_name(detail::byte_data(name), name.size(), response,
                                               value);
            });
        }

        /**
         * @brief Read ISO binary data using -1 for the current file or a short identifier.
         * @param short_identifier ISO short file identifier, using zero when the current file
         * applies.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param length Requested byte count; zero retains the command-specific remaining-data
         * meaning.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> iso_read_binary(std::optional<FileNumber> short_identifier,
                                      std::uint32_t offset, std::uint32_t length,
                                      std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.iso_read_binary(optional_short_id(short_identifier), offset, length,
                                            value);
            });
        }

        /**
         * @brief Update ISO binary data using -1 for the current file or a short identifier.
         * @param short_identifier ISO short file identifier, using zero when the current file
         * applies.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> iso_update_binary(std::optional<FileNumber> short_identifier,
                                        std::uint32_t offset, const Bytes& data,
                                        std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.iso_update_binary(optional_short_id(short_identifier), offset,
                                              detail::byte_data(data), data.size(), value);
            });
        }

        /**
         * @brief Read ISO records using explicit ISO selection semantics.
         * @param record Record number selected by the native or ISO command.
         * @param short_identifier ISO short file identifier, using zero when the current file
         * applies.
         * @param selection ISO P2 file-selection control byte.
         * @param length Requested byte count; zero retains the command-specific remaining-data
         * meaning.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> iso_read_records(IsoRecord record, FileNumber short_identifier,
                                       std::uint32_t selection, std::uint32_t length,
                                       std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.iso_read_records(record.value(), short_identifier.value(), selection,
                                             length, value);
            });
        }

        /**
         * @brief Append one ISO record.
         * @param short_identifier ISO short file identifier, using zero when the current file
         * applies.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> iso_append_record(FileNumber short_identifier, const Bytes& data,
                                        std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.iso_append_record(short_identifier.value(), detail::byte_data(data),
                                              data.size(), value);
            });
        }

        /**
         * @brief Read an unverified ISO challenge of eight or sixteen bytes.
         * @param length Requested byte count; zero retains the command-specific remaining-data
         * meaning.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes> iso_get_challenge(std::uint32_t length,
                                        std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.iso_get_challenge(length, value);
            });
        }

        /**
         * @brief Send a caller-prepared ISO external-authentication cryptogram.
         * @param key_number Validated native key selector.
         * @param application_key True for application-key scope; false for the PICC master key.
         * @param algorithm ISO authentication algorithm reference byte.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes>
        iso_external_authenticate(KeyNumber key_number, bool application_key,
                                  std::uint32_t algorithm, const Bytes& data,
                                  std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.iso_external_authenticate(key_number.value(), application_key ? 1U : 0U,
                                                      algorithm, detail::byte_data(data),
                                                      data.size(), value);
            });
        }

        /**
         * @brief Send a caller-prepared ISO internal-authentication challenge.
         * @param key_number Validated native key selector.
         * @param application_key True for application-key scope; false for the PICC master key.
         * @param algorithm ISO authentication algorithm reference byte.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param timeout Complete logical-operation timeout.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Bytes>
        iso_internal_authenticate(KeyNumber key_number, bool application_key,
                                  std::uint32_t algorithm, const Bytes& data,
                                  std::chrono::milliseconds timeout = default_timeout) {
            return timed_buffer(timeout, [&](std::uint32_t value) {
                return raw_.iso_internal_authenticate(key_number.value(), application_key ? 1U : 0U,
                                                      algorithm, detail::byte_data(data),
                                                      data.size(), value);
            });
        }

    private:

        /**
         * @brief Adopt the only raw managed-card owner returned by open().
         * @param card Sole raw managed-card owner returned by open().
         */
        explicit Card(raw::Card card) noexcept : raw_(std::move(card)) {}

        /**
         * @brief Convert one scoped enum to its exact C integer.
         * @param value Strong communication-mode value to convert without reinterpretation.
         * @return The exact unsigned C ABI value for the communication mode.
         */
        static std::uint32_t scalar(CommunicationMode value) noexcept {
            return static_cast<std::uint32_t>(value);
        }

        /**
         * @brief Convert an optional ISO identifier to the C ABI sentinel representation.
         * @param value Optional ISO file identifier to encode.
         * @return The ISO identifier value, or minus one when absent.
         */
        static std::int32_t optional_iso_id(const std::optional<IsoFileId>& value) noexcept {
            return value ? static_cast<std::int32_t>(value->value()) : -1;
        }

        /**
         * @brief Convert an optional key set to the C ABI sentinel representation.
         * @param value Optional EV3 key-set number to encode.
         * @return The key-set number, or minus one when absent.
         */
        static std::int32_t optional_key_set(const std::optional<KeySetNumber>& value) noexcept {
            return value ? static_cast<std::int32_t>(value->value()) : -1;
        }

        /**
         * @brief Convert an optional short ISO identifier to the C ABI sentinel representation.
         * @param value Optional ISO short file identifier to encode.
         * @return The short file identifier, or minus one when absent.
         */
        static std::int32_t optional_short_id(const std::optional<FileNumber>& value) noexcept {
            return value ? static_cast<std::int32_t>(value->value()) : -1;
        }

        /**
         * @brief Reject an invalid or out-of-range direct native authentication key locally.
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        static Result<void> validate_direct_authentication(KeyNumber key_number,
                                                           const Aes128Key& key) {
            if (key_number.value() > 31) {
                return Result<void>::failure(
                    detail::invalid_argument("native authentication key number exceeds 31"));
            }
            if (!key.valid()) {
                return Result<void>::failure(
                    detail::invalid_argument("AES-128 key ownership is empty"));
            }
            return Result<void>::success();
        }

        /**
         * @brief Normalize a derivation failure to truthful pre-I/O delivery evidence.
         * @param error Per-call C error storage paired with the returned status.
         * @return Owned redacted failure evidence.
         */
        static Error before_io(Error error) {
            error.outcome = Outcome::not_sent;
            error.device_status = 0;
            return error;
        }

        /**
         * @brief Invoke one custom deriver exactly once after local context validation.
         * @param master_key Live AES-128 master key borrowed only for derivation.
         * @param deriver Synchronous application-defined derivation implementation.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        static Result<Aes128Key> derive_authentication_key(const Aes128Key& master_key,
                                                           Aes128KeyDeriver& deriver,
                                                           const Aes128DerivationContext& context) {
            return derive_key(master_key, deriver, context, KeyPurpose::authentication);
        }

        /**
         * @brief Invoke one custom deriver exactly once for a validated general key purpose.
         * @param master_key Live AES-128 master key borrowed only for derivation.
         * @param deriver Synchronous application-defined derivation implementation.
         * @param context Borrowed callback or derivation context that remains valid through the
         * call.
         * @param expected_purpose Key purpose required by the operation consuming the resolved key.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        static Result<Aes128Key> derive_key(const Aes128Key& master_key, Aes128KeyDeriver& deriver,
                                            const Aes128DerivationContext& context,
                                            KeyPurpose expected_purpose) {
            if (!master_key.valid()) {
                return Result<Aes128Key>::failure(
                    detail::invalid_argument("AES-128 master key ownership is empty"));
            }
            if (context.purpose != expected_purpose) {
                return Result<Aes128Key>::failure(
                    detail::invalid_argument("key derivation purpose does not match operation"));
            }
            const auto diversification_size = context.diversification_input.size();
            const auto user_size = context.user_context.size();
            if (diversification_size > 65536 || user_size > 65536 ||
                diversification_size > 65536 - user_size) {
                return Result<Aes128Key>::failure(detail::invalid_argument(
                    "diversification input and user context exceed the 64-KiB bound"));
            }
            auto key = deriver.derive(master_key, context);
            if (!key) {
                return Result<Aes128Key>::failure(before_io(std::move(key).error()));
            }
            if (!key.value().valid()) {
                return Result<Aes128Key>::failure({ErrorCode::crypto, Outcome::not_sent, 0,
                                                   "AES-128 deriver returned an invalid key"});
            }
            return key;
        }

        /**
         * @brief Validate a non-authentication provider request before invoking the C ABI.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param expected_purpose Key purpose required by the operation consuming the resolved key.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        static Result<void> validate_provider_request(const KeyRequest& request,
                                                      KeyPurpose expected_purpose) {
            auto checked = detail::validate_key_request(request);
            if (!checked) {
                return checked;
            }
            if (request.context.purpose != expected_purpose) {
                return Result<void>::failure(
                    detail::invalid_argument("key request purpose does not match operation"));
            }
            return Result<void>::success();
        }

        /** @brief Check request purpose, profile, scope, and selector before provider invocation.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param expected Authentication profile required for the provider request.
         * @param iso True requires ISO authentication scope; false requires native authentication
         * scope.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        static Result<void> validate_provider_authentication(const KeyRequest& request,
                                                             AuthenticationProfile expected,
                                                             bool iso) {
            auto checked = detail::validate_key_request(request);
            if (!checked) {
                return checked;
            }
            if (!request.authentication_profile || *request.authentication_profile != expected) {
                return Result<void>::failure(detail::invalid_argument(
                    "key request authentication profile does not match operation"));
            }
            if (iso) {
                if (request.scope != KeyScope::iso_picc &&
                    request.scope != KeyScope::iso_application) {
                    return Result<void>::failure(
                        detail::invalid_argument("ISO AES requires an ISO key scope"));
                }
            } else if (request.scope != KeyScope::native) {
                return Result<void>::failure(
                    detail::invalid_argument("native AES requires native key scope"));
            }
            return Result<void>::success();
        }

        /**
         * @brief Convert a duration once, then invoke one typed raw operation.
         * @param timeout Complete logical-operation timeout.
         * @param function C ABI lifecycle function to invoke exactly once.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        template <class T, class Function>
        static Result<T> timed(std::chrono::milliseconds timeout, Function function) {
            auto milliseconds = detail::timeout_milliseconds(timeout);
            if (!milliseconds) {
                return Result<T>::failure(std::move(milliseconds).error());
            }
            return function(milliseconds.value());
        }

        /**
         * @brief Convert and copy one owned raw buffer without repeating card I/O.
         * @param timeout Complete logical-operation timeout.
         * @param function C ABI lifecycle function to invoke exactly once.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        template <class Function>
        static Result<Bytes> timed_buffer(std::chrono::milliseconds timeout, Function function) {
            auto result = timed<raw::Buffer>(timeout, std::move(function));
            if (!result) {
                return Result<Bytes>::failure(std::move(result).error());
            }
            return Result<Bytes>::success(result.value().copy());
        }

        /**
         * @brief Dispatch one value mutation through a selected exact C ABI member.
         * @param function C ABI lifecycle function to invoke exactly once.
         * @param file Native file number targeted by the command.
         * @param amount Unsigned value adjustment encoded by the credit or debit command.
         * @param communication Communication mode required by the target file.
         * @param timeout Complete logical-operation timeout.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void>
        value_mutation(Result<void> (raw::Card::*function)(std::uint32_t, std::uint32_t,
                                                           std::uint32_t, std::uint32_t),
                       FileNumber file, std::uint32_t amount, CommunicationMode communication,
                       std::chrono::milliseconds timeout) {
            return timed<void>(timeout, [&](std::uint32_t value) {
                return (raw_.*function)(file.value(), amount, scalar(communication), value);
            });
        }

        raw::Card raw_; /**< Sole result-based managed C ABI owner used by the friendly facade. */
    };
} // namespace desfire::cpp17
