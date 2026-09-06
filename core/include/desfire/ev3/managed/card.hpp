/**
 * @file card.hpp
 * @brief Serialized checked operations for one managed DESFire EV3 connection.
 */
#pragma once

#include "transaction_plan.hpp"

#include <desfire/ev3/iso7816/checked/command.hpp>
#include <desfire/ev3/iso7816/checked/response.hpp>
#include <desfire/ev3/model/authentication.hpp>
#include <desfire/ev3/model/version.hpp>
#include <desfire/ev3/native/checked/applications.hpp>
#include <desfire/ev3/native/checked/card_management.hpp>
#include <desfire/ev3/native/checked/files.hpp>
#include <desfire/ev3/native/checked/keys.hpp>
#include <desfire/ev3/native/checked/transactions.hpp>
#include <desfire/ev3/security/key_derivation/aes128.hpp>
#include <desfire/foundation/crypto_provider.hpp>
#include <desfire/foundation/transport.hpp>

#include <array>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace desfire::ev3::managed {

    class CardImpl;

    /**
     * @brief Manage one activated DESFire EV3 connection and all of its authentication state.
     *
     * Every operation serializes from preflight through the final native additional frame or ISO
     * continuation. Different Card objects may run concurrently. `cancel()` may run concurrently
     * and bypasses the operation lock. An unknown delivery, card-generation change, or protected
     * integrity failure makes the object unusable until a successful `reset()` or reconnect.
     */
    class Card final : public std::enable_shared_from_this<Card> {
    public:

        /**
         * @brief Create a managed card around one exclusively owned activated transport.
         * @param transport Shared transport whose logical ownership transfers to this Card.
         * @param crypto Shared AES primitive provider retained for authentication and messaging.
         * @return Shared Card ownership, or invalid_argument for an absent dependency.
         * @warning Do not use the transport through another protocol object while this Card lives.
         */
        static Result<std::shared_ptr<Card>> connect(std::shared_ptr<CardTransport> transport,
                                                     std::shared_ptr<CryptoProvider> crypto);

        /** @brief Erase session state and release the transport and crypto dependencies. */
        ~Card();

        /** @brief Managed card state and transport identity cannot be copied. */
        Card(const Card&) = delete;

        /** @brief Managed card state and transport identity cannot be copy-assigned. */
        Card& operator=(const Card&) = delete;

        /** @brief A live managed card retains stable shared identity and cannot be moved. */
        Card(Card&&) = delete;

        /** @brief A live managed card retains stable shared identity and cannot be move-assigned.
         */
        Card& operator=(Card&&) = delete;

        /**
         * @brief Read and parse fixed GetVersion information across native AF frames.
         * @param options Positive total deadline and cancellation controls.
         * @return Parsed version descriptor or transport/card/parser evidence.
         */
        Result<model::VersionInfo> get_version(const ExchangeOptions& options = {});

        /**
         * @brief Read the three-byte free-memory count from the current PICC state.
         * @param options Positive total deadline and cancellation controls.
         * @return Free bytes as a 24-bit value, or failure evidence.
         */
        Result<std::uint32_t> free_memory(const ExchangeOptions& options = {});

        /**
         * @brief Select one native application and clear authentication bound to the old selection.
         * @param id Validated 24-bit application identifier; zero selects the PICC application.
         * @param options Positive total deadline and cancellation controls.
         * @return Success after an empty card acknowledgement, or failure evidence.
         * @warning Local session keys are erased before selection because card state can change
         * even when the final response is lost or rejected.
         */
        Result<void> select_application(model::ApplicationId id,
                                        const ExchangeOptions& options = {});

        /**
         * @brief List unique native file numbers in their card-reported order.
         * @param options Positive total deadline and cancellation controls.
         * @return Zero through 32 validated file numbers, or failure evidence.
         */
        Result<std::vector<model::FileNumber>> file_ids(const ExchangeOptions& options = {});

        /**
         * @brief Authenticate Standard AES using one direct move-only exact key.
         * @param key_number Validated native key selector.
         * @param key Exact AES-128 key consumed and wiped after this attempt.
         * @param options One positive deadline and cancellation token for both frames.
         * @return Success after mutual proof and session installation.
         */
        Result<void> authenticate_standard_aes(model::KeyNumber key_number,
                                               security::key_derivation::Aes128Key key,
                                               const ExchangeOptions& options = {});

        /**
         * @brief Derive exactly once and authenticate Standard AES before any card frame.
         * @param master_key Exact master key consumed and wiped after this attempt.
         * @param deriver Caller-owned synchronous derivation policy.
         * @param context Authentication-purpose Standard AES context and native key selector.
         * @param options One positive deadline and cancellation token for resolution and frames.
         * @return Success after derivation, mutual proof, and session installation.
         */
        Result<void>
        authenticate_standard_aes(security::key_derivation::Aes128Key master_key,
                                  security::key_derivation::Aes128KeyDeriver& deriver,
                                  const security::key_derivation::Aes128DerivationContext& context,
                                  const ExchangeOptions& options = {});

        /**
         * @brief Resolve exactly once and authenticate Standard AES before any card frame.
         * @param provider Caller-owned synchronous exportable-key provider.
         * @param request Native Standard AES authentication request and non-secret key reference.
         * @param options One positive deadline and cancellation token for resolution and frames.
         * @return Success after resolution, mutual proof, and session installation.
         */
        Result<void>
        authenticate_standard_aes(security::key_derivation::Aes128KeyProvider& provider,
                                  const security::key_derivation::KeyRequest& request,
                                  const ExchangeOptions& options = {});

        /** @brief Establish EV2 First using one direct move-only exact key. */
        Result<model::AuthenticationInfo>
        authenticate_ev2_first_aes(model::KeyNumber key_number,
                                   security::key_derivation::Aes128Key key,
                                   const ExchangeOptions& options = {});

        /** @brief Establish EV2 First with explicit capabilities and one direct exact key. */
        Result<model::AuthenticationInfo> authenticate_ev2_first_aes_with_capabilities(
            model::KeyNumber key_number, security::key_derivation::Aes128Key key,
            ByteView pcd_capabilities, const ExchangeOptions& options = {});

        /** @brief Derive exactly once and establish EV2 First before any card frame. */
        Result<model::AuthenticationInfo>
        authenticate_ev2_first_aes(security::key_derivation::Aes128Key master_key,
                                   security::key_derivation::Aes128KeyDeriver& deriver,
                                   const security::key_derivation::Aes128DerivationContext& context,
                                   const ExchangeOptions& options = {});

        /** @brief Derive exactly once and establish EV2 First with explicit capabilities. */
        Result<model::AuthenticationInfo> authenticate_ev2_first_aes_with_capabilities(
            security::key_derivation::Aes128Key master_key,
            security::key_derivation::Aes128KeyDeriver& deriver,
            const security::key_derivation::Aes128DerivationContext& context,
            ByteView pcd_capabilities, const ExchangeOptions& options = {});

        /** @brief Resolve exactly once and establish EV2 First before any card frame. */
        Result<model::AuthenticationInfo>
        authenticate_ev2_first_aes(security::key_derivation::Aes128KeyProvider& provider,
                                   const security::key_derivation::KeyRequest& request,
                                   const ExchangeOptions& options = {});

        /** @brief Resolve exactly once and establish EV2 First with explicit capabilities. */
        Result<model::AuthenticationInfo> authenticate_ev2_first_aes_with_capabilities(
            security::key_derivation::Aes128KeyProvider& provider,
            const security::key_derivation::KeyRequest& request, ByteView pcd_capabilities,
            const ExchangeOptions& options = {});

        /** @brief Replace EV2 session keys through NonFirst using one direct exact key. */
        Result<model::AuthenticationInfo>
        authenticate_ev2_non_first_aes(model::KeyNumber key_number,
                                       security::key_derivation::Aes128Key key,
                                       const ExchangeOptions& options = {});

        /** @brief Derive exactly once and authenticate EV2 NonFirst before any card frame. */
        Result<model::AuthenticationInfo> authenticate_ev2_non_first_aes(
            security::key_derivation::Aes128Key master_key,
            security::key_derivation::Aes128KeyDeriver& deriver,
            const security::key_derivation::Aes128DerivationContext& context,
            const ExchangeOptions& options = {});

        /** @brief Resolve exactly once and authenticate EV2 NonFirst before any card frame. */
        Result<model::AuthenticationInfo>
        authenticate_ev2_non_first_aes(security::key_derivation::Aes128KeyProvider& provider,
                                       const security::key_derivation::KeyRequest& request,
                                       const ExchangeOptions& options = {});

        /**
         * @brief Execute one immutable checked native command with current session protection.
         * @param command Borrowed command that remains valid until this synchronous call returns.
         * @param options Positive total deadline and cancellation controls.
         * @return Verified status-free response within the command's declared bounds.
         * @warning No frame or mutation is retried after uncertain delivery.
         */
        Result<Bytes> execute(const native::checked::Command& command,
                              const ExchangeOptions& options = {});

        /**
         * @brief Validate live target settings, stage a plan, and commit under one card lock.
         * @param plan One through 128 owned backup/value/record mutations borrowed for this call.
         * @param return_mac Request the 12-byte transaction counter and MAC receipt.
         * @param options One positive deadline shared by validation, mutations, and commit.
         * @return Empty or 12-byte commit receipt after every integrity check succeeds.
         * @pre No earlier staged mutation is unintentionally pending on the card.
         * @warning Failure after the first staged mutation has unknown transaction outcome and
         * invalidates this Card. The operation never sends an automatic abort or retry.
         */
        Result<Bytes> execute_transaction(const TransactionPlan& plan, bool return_mac = false,
                                          const ExchangeOptions& options = {});

        /**
         * @brief Execute one actual ISO/IEC 7816 command, separate from native ISO wrapping.
         * @param command Borrowed validated ISO command.
         * @param options Positive total deadline and cancellation controls.
         * @return ISO response retaining its full status word and verified data when authenticated.
         * @warning DF selection clears authentication; EF selection retains an ISO session.
         */
        Result<iso7816::checked::Response> iso_command(const iso7816::checked::Command& command,
                                                       const ExchangeOptions& options = {});

        /**
         * @brief Establish ISO mutual AES authentication using one direct exact key.
         * @param key Validated ISO key reference sent to the card.
         * @param aes_key Exact AES-128 key consumed and wiped after this attempt.
         * @param options One positive deadline and cancellation token for all three APDUs.
         * @return Success after verified mutual proof and ISO session installation.
         */
        Result<void> authenticate_iso_aes(iso7816::checked::KeyReference key,
                                          security::key_derivation::Aes128Key aes_key,
                                          const ExchangeOptions& options = {});

        /**
         * @brief Derive exactly once and establish ISO mutual AES authentication before any APDU.
         * @param key Validated ISO key reference sent to the card.
         * @param master_key Exact master key consumed and wiped after this attempt.
         * @param deriver Caller-owned synchronous derivation policy.
         * @param context Authentication-purpose derivation context.
         * @param options One positive deadline and cancellation token for derivation and APDUs.
         * @return Success after derivation, mutual proof, and ISO session installation.
         */
        Result<void>
        authenticate_iso_aes(iso7816::checked::KeyReference key,
                             security::key_derivation::Aes128Key master_key,
                             security::key_derivation::Aes128KeyDeriver& deriver,
                             const security::key_derivation::Aes128DerivationContext& context,
                             const ExchangeOptions& options = {});

        /**
         * @brief Resolve exactly once and establish ISO mutual AES authentication before any APDU.
         * @param key Validated ISO key reference sent to the card.
         * @param provider Caller-owned synchronous exportable-key provider.
         * @param request ISO authentication request and non-secret provider reference.
         * @param options One positive deadline and cancellation token for resolution and APDUs.
         * @return Success after resolution, mutual proof, and ISO session installation.
         */
        Result<void> authenticate_iso_aes(iso7816::checked::KeyReference key,
                                          security::key_derivation::Aes128KeyProvider& provider,
                                          const security::key_derivation::KeyRequest& request,
                                          const ExchangeOptions& options = {});

        /**
         * @brief Read unauthenticated DF-name records while preserving physical frame boundaries.
         * @param options Positive total deadline and cancellation controls.
         * @return Decoded records, or a pre-I/O error while native/ISO authentication is active.
         */
        Result<std::vector<native::checked::DfName>> df_names(const ExchangeOptions& options = {});

        /** @brief List unique application identifiers after complete response validation. */
        Result<std::vector<model::ApplicationId>>
        application_ids(const ExchangeOptions& options = {});

        /** @brief List unique ISO file identifiers in their card-reported order. */
        Result<std::vector<std::uint16_t>> iso_file_ids(const ExchangeOptions& options = {});

        /** @brief Read and strictly parse one file's settings and extensions. */
        Result<model::FileSettings> file_settings(model::FileNumber file,
                                                  const ExchangeOptions& options = {});

        /** @brief Read one signed value-file balance using the requested protection mode. */
        Result<std::int32_t> value(model::FileNumber file, model::CommunicationMode mode,
                                   const ExchangeOptions& options = {});

        /** @brief Read bytes at an offset; zero length requests the documented file remainder. */
        Result<Bytes> read_data(model::FileNumber file, model::Offset offset,
                                model::ByteCount length, model::CommunicationMode mode,
                                const ExchangeOptions& options = {});

        /** @brief Write borrowed bytes once; backup-file commit remains an explicit operation. */
        Result<void> write_data(model::FileNumber file, model::Offset offset, ByteView data,
                                model::CommunicationMode mode, const ExchangeOptions& options = {});

        /** @brief Create a checked AES application with optional ISO and key-set fields. */
        Result<void> create_application(const model::ApplicationConfiguration& configuration,
                                        const ExchangeOptions& options = {});

        /** @brief Permanently delete one nonzero application after checked protected execution. */
        Result<void> delete_application(model::ApplicationId id,
                                        const ExchangeOptions& options = {});

        /**
         * @brief Create a delegated AES application using issuer-produced authorization data.
         * @param configuration Checked AID, DAM slot/quota, keys, and optional ISO metadata.
         * @param encrypted_default_key Exact 32-byte EncK value borrowed for this call.
         * @param dam_mac Exact eight-byte authorization MAC borrowed for this call.
         * @param options Positive total deadline and cancellation controls.
         * @return Success after protected execution and response verification.
         */
        Result<void>
        create_delegated_application(const model::DelegatedApplicationConfiguration& configuration,
                                     ByteView encrypted_default_key, ByteView dam_mac,
                                     const ExchangeOptions& options = {});

        /** @brief Read and strictly decode one delegated-application slot. */
        Result<native::checked::DelegatedApplicationInfo>
        delegated_application_info(std::uint16_t slot, const ExchangeOptions& options = {});

        /** @brief Delete one delegated application using an exact issuer-generated DAM MAC. */
        Result<void> delete_delegated_application(model::ApplicationId id, ByteView dam_mac,
                                                  const ExchangeOptions& options = {});

        /** @brief Read and strictly decode current application key settings. */
        Result<model::KeySettings> key_settings(const ExchangeOptions& options = {});

        /** @brief Change the one-byte application key settings through Full communication. */
        Result<void> change_key_settings(Byte settings, const ExchangeOptions& options = {});

        /** @brief Read one active or explicitly selected key-set version byte. */
        Result<Byte> key_version(model::KeyNumber key, std::optional<Byte> key_set = {},
                                 const ExchangeOptions& options = {});

        /** @brief Read two through 16 key-set version bytes in card order. */
        Result<Bytes> key_set_versions(const ExchangeOptions& options = {});

        /**
         * @brief Replace one AES key using the active authenticated key context.
         * @param key Target native key selector.
         * @param new_key Exact 16-byte replacement AES key borrowed for this call.
         * @param version Replacement key version byte.
         * @param authenticated_key Key selector used by the current verified session.
         * @param old_key Exact 16-byte current target key when changing another key; empty when
         * changing the authenticated active-set key.
         * @param key_set Optional EV2 key-set selector from zero through 15.
         * @param picc_master_key Apply the documented PICC master-key version-zero rule.
         * @param options Positive total deadline and cancellation controls.
         * @return Success after protected card acknowledgement.
         */
        Result<void> change_aes_key(model::KeyNumber key, ByteView new_key, Byte version,
                                    model::KeyNumber authenticated_key, ByteView old_key = {},
                                    std::optional<Byte> key_set = {}, bool picc_master_key = false,
                                    const ExchangeOptions& options = {});

        /** @brief Initialize one AES key set numbered zero through 15. */
        Result<void> initialize_key_set(Byte key_set, const ExchangeOptions& options = {});

        /** @brief Finalize one AES key set with its caller-selected version byte. */
        Result<void> finalize_key_set(Byte key_set, Byte version,
                                      const ExchangeOptions& options = {});

        /** @brief Activate one AES key set and erase authentication after verified success. */
        Result<void> roll_key_set(Byte key_set, const ExchangeOptions& options = {});

        /** @brief Create a checked positive-size standard or backup data file. */
        Result<void> create_data_file(const model::DataFileConfiguration& configuration,
                                      const ExchangeOptions& options = {});

        /** @brief Create a checked value file with ordered signed limits. */
        Result<void> create_value_file(const model::ValueFileConfiguration& configuration,
                                       const ExchangeOptions& options = {});

        /** @brief Create a checked positive-size linear or cyclic record file. */
        Result<void> create_record_file(const model::RecordFileConfiguration& configuration,
                                        const ExchangeOptions& options = {});

        /** @brief Create one transaction-MAC file using an exact 16-byte AES key. */
        Result<void> create_transaction_mac_file(model::FileNumber file, model::AccessRights access,
                                                 ByteView aes_key, Byte key_version,
                                                 const ExchangeOptions& options = {});

        /** @brief Permanently delete one validated native file number. */
        Result<void> delete_file(model::FileNumber file, const ExchangeOptions& options = {});

        /** @brief Read the exact SDM counter and reserved bytes using Plain or Full mode. */
        Result<native::checked::FileCounters> file_counters(model::FileNumber file,
                                                            model::CommunicationMode mode,
                                                            const ExchangeOptions& options = {});

        /** @brief Change checked file access/protection settings; unsupported SDM fails pre-I/O. */
        Result<void> change_file_settings(const model::FileSettingsChange& configuration,
                                          const ExchangeOptions& options = {});

        /** @brief Stage one checked nonnegative debit for explicit later commit or abort. */
        Result<void> debit(model::FileNumber file, std::uint32_t amount,
                           model::CommunicationMode mode, const ExchangeOptions& options = {});

        /** @brief Stage one checked nonnegative credit for explicit later commit or abort. */
        Result<void> credit(model::FileNumber file, std::uint32_t amount,
                            model::CommunicationMode mode, const ExchangeOptions& options = {});

        /** @brief Stage one checked limited credit for explicit later commit or abort. */
        Result<void> limited_credit(model::FileNumber file, std::uint32_t amount,
                                    model::CommunicationMode mode,
                                    const ExchangeOptions& options = {});

        /** @brief Stage a value restore from source into target using Plain or MAC mode. */
        Result<void> restore_transfer(model::FileNumber target, model::FileNumber source,
                                      model::CommunicationMode mode,
                                      const ExchangeOptions& options = {});

        /** @brief Read records from an index with a hard clear-response byte limit. */
        Result<Bytes> read_records(model::FileNumber file, model::Offset first_record,
                                   model::ByteCount count, model::CommunicationMode mode,
                                   std::size_t maximum_response = 16U * 1024U * 1024U,
                                   const ExchangeOptions& options = {});

        /** @brief Append one record fragment at a byte offset for explicit later commit. */
        Result<void> write_record(model::FileNumber file, model::Offset offset, ByteView data,
                                  model::CommunicationMode mode,
                                  const ExchangeOptions& options = {});

        /** @brief Update one existing record and stage it for explicit later commit. */
        Result<void> update_record(model::FileNumber file, model::Offset record,
                                   model::Offset offset, ByteView data,
                                   model::CommunicationMode mode,
                                   const ExchangeOptions& options = {});

        /** @brief Stage removal of every record in one file for explicit later commit. */
        Result<void> clear_record_file(model::FileNumber file, const ExchangeOptions& options = {});

        /** @brief Commit pending changes once and optionally return a 12-byte transaction receipt.
         */
        Result<Bytes> commit_transaction(bool return_mac = false,
                                         const ExchangeOptions& options = {});

        /** @brief Abort pending changes once; ambiguous delivery never triggers a retry. */
        Result<void> abort_transaction(const ExchangeOptions& options = {});

        /** @brief Commit an exact 16-byte reader identifier and return its verified 16-byte echo.
         */
        Result<Bytes> commit_reader_id(ByteView reader_id, const ExchangeOptions& options = {});

        /** @brief Read and validate the authenticated UID using the option-omitted request. */
        Result<native::checked::CardUid> card_uid(const ExchangeOptions& options = {});

        /**
         * @brief Read the authenticated UID using one explicit documented NUID request variant.
         * @param request Omit the byte, suppress NUID, or request its four-byte suffix.
         * @param options Positive total deadline and cancellation controls.
         * @return Validated UID and optional NUID without partial data on failure.
         */
        Result<native::checked::CardUid> card_uid(native::checked::CardUidRequest request,
                                                  const ExchangeOptions& options = {});

        /** @brief Read exactly 56 originality-signature bytes; offline verification is separate. */
        Result<std::array<Byte, 56>> originality_signature(const ExchangeOptions& options = {});

        /**
         * @brief Permanently format the PICC after checked authenticated execution.
         * @param options Positive timeout and cooperative cancellation controls.
         * @return Success after the card confirms formatting, or precise failure evidence.
         */
        Result<void> format_picc(const ExchangeOptions& options = {});

        /** @brief Set documented PICC option-zero feature flags through Full communication. */
        Result<void> set_picc_configuration(const model::PiccConfiguration& configuration,
                                            const ExchangeOptions& options = {});

        /** @brief Set the exact nine-byte option-five capability record. */
        Result<void>
        set_capability_configuration(const model::CapabilityConfiguration& configuration,
                                     const ExchangeOptions& options = {});

        /** @brief Replace the PICC default AES key and its version using exact 16-byte material. */
        Result<void> set_default_aes_key(ByteView aes_key, Byte key_version,
                                         const ExchangeOptions& options = {});

        /** @brief Set a complete two through 20-byte ATS including its matching length byte. */
        Result<void> set_ats(ByteView ats, const ExchangeOptions& options = {});

        /** @brief Set the two-byte user ATQA field in native little-endian order. */
        Result<void> set_atqa(std::uint16_t atqa, const ExchangeOptions& options = {});

        /**
         * @brief Erase local native and ISO authentication without card I/O.
         * @return Success, or busy for callback reentry.
         * @warning When authentication existed, ordinary I/O remains blocked until selection,
         * EV2 First authentication, or transport reset re-synchronizes the card.
         */
        Result<void> reset_authentication();

        /**
         * @brief Erase local state and reset the reader/card connection.
         * @return Transport reset evidence; failure leaves this Card unusable.
         */
        Result<void> reset();

        /**
         * @brief Ask the transport to interrupt pending I/O without taking the Card lock.
         */
        void cancel() noexcept;

    private:

        /**
         * @brief Adopt a fully initialized private implementation.
         * @param impl Exclusive implementation ownership.
         */
        explicit Card(std::unique_ptr<CardImpl> impl);

        /**
         * @brief Validate managed state before direct or host-resolved authentication.
         * @param require_ev2_session Require active EV2 First state for NonFirst.
         * @param options Positive timeout and cancellation controls checked before resolution.
         * @return Success before resolver/card access or precise local failure evidence.
         */
        Result<void> authentication_preflight_locked(bool require_ev2_session,
                                                     const ExchangeOptions& options);

        /**
         * @brief Execute one clear discovery/selection command while the Card lock is held.
         * @param command Native instruction byte.
         * @param data Status-free command data.
         * @param options Complete logical-command controls.
         * @param operation Redacted operation name for rejection diagnostics.
         * @return Status-free response data or failure evidence.
         */
        Result<Bytes> execute_plain_locked(Byte command, ByteView data,
                                           const ExchangeOptions& options,
                                           std::string_view operation);

        /**
         * @brief Run EV2 First or NonFirst authentication while the Card lock is held.
         * @param first True for First and false for NonFirst.
         * @param key_number Validated native key selector.
         * @param key Exact live AES-128 owner borrowed for this exchange.
         * @param pcd_capabilities Zero through six First capability bytes; empty for NonFirst.
         * @param options One deadline and cancellation token for both frames.
         * @return Verified public EV2 authentication information.
         */
        Result<model::AuthenticationInfo>
        authenticate_ev2_locked(bool first, model::KeyNumber key_number,
                                const security::key_derivation::Aes128Key& key,
                                ByteView pcd_capabilities, const ExchangeOptions& options);

        /**
         * @brief Run Standard AES authentication while the Card lock is held.
         * @param key_number Validated native key selector.
         * @param key Exact live AES-128 owner borrowed for this exchange.
         * @param options One deadline and cancellation token for both frames.
         * @return Success after verified session installation.
         */
        Result<void>
        authenticate_standard_aes_locked(model::KeyNumber key_number,
                                         const security::key_derivation::Aes128Key& key,
                                         const ExchangeOptions& options);

        /**
         * @brief Run ISO mutual AES authentication while the Card lock is held.
         * @param key Validated ISO key reference sent to the card.
         * @param aes_key Exact live AES-128 owner borrowed for this exchange.
         * @param options One deadline and cancellation token for all authentication APDUs.
         * @return Success after verified ISO session installation.
         */
        Result<void> authenticate_iso_aes_locked(iso7816::checked::KeyReference key,
                                                 const security::key_derivation::Aes128Key& aes_key,
                                                 const ExchangeOptions& options);

        /**
         * @brief Erase all sessions and mark managed state unusable after ambiguity.
         */
        void invalidate_locked() noexcept;

        /**
         * @brief Execute one checked command while the caller holds the Card lock.
         * @param command Borrowed immutable command.
         * @param options Complete logical-command controls.
         * @return Verified clear response or failure evidence.
         */
        Result<Bytes> execute_locked(const native::checked::Command& command,
                                     const ExchangeOptions& options);

        /**
         * @brief Execute already borrowed planned mutations while the Card lock is held.
         * @param operations One through 128 checked transactional mutations.
         * @param return_mac Request a transaction-MAC receipt.
         * @param options One deadline for validation, staging, and commit.
         * @return Commit response or failure evidence.
         */
        Result<Bytes>
        execute_transaction_locked(std::span<const native::checked::Command> operations,
                                   bool return_mac, const ExchangeOptions& options);

        std::unique_ptr<CardImpl> impl_; ///< Owned managed-card implementation state.
    };

} // namespace desfire::ev3::managed
