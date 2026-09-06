/** @file ev3_long_exchange_test.cpp
 * @brief Real workflow scenarios over independent native/wrapped wire fixtures.
 */
#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <desfire/crypto/openssl.hpp>
#include <desfire/ev3/managed/card.hpp>
#include <desfire/ev3/native/checked/files.hpp>
#include <desfire/ev3/native/checked/transactions.hpp>
#include <desfire/transports/callback.hpp>
#include <desfire/transports/replay.hpp>
#include <iostream>
#include <mutex>
#include <optional>
#include <thread>

namespace {
    namespace managed = desfire::ev3::managed;

    using namespace desfire;
    using namespace desfire::ev3::model;
    using namespace desfire::ev3::native::checked;
    using namespace desfire::transports;

    /** @brief Fail immediately with a stable assertion description. */
    void expect(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << '\n';
            std::exit(1);
        }
    }

    /** @brief Construct independently specified wire envelopes, without SDK codec helpers. */
    Bytes request(Framing framing, Byte opcode, ByteView payload) {
        Bytes result;
        if (framing == Framing::native) {
            result.push_back(opcode);
        } else {
            result = {0x90, opcode, 0, 0};
            if (!payload.empty()) {
                result.push_back(static_cast<Byte>(payload.size()));
            }
        }
        result.insert(result.end(), payload.begin(), payload.end());
        if (framing == Framing::iso7816) {
            result.push_back(0);
        }
        return result;
    }

    /** @brief Place native status first or wrapped SW1/SW2 last, independently of SDK decoding. */
    Bytes response(Framing framing, Byte status, ByteView payload = {}) {
        Bytes result;
        if (framing == Framing::native) {
            result.push_back(status);
        }
        result.insert(result.end(), payload.begin(), payload.end());
        if (framing == Framing::iso7816) {
            result.push_back(0x91);
            result.push_back(status);
        }
        return result;
    }

    /** @brief Fix the fixture's physical native frame to 32 bytes, including its opcode. */
    TransportCapabilities capabilities(Framing framing) {
        TransportCapabilities c;
        c.framing = framing;
        c.max_native_frame = 32;
        c.max_transmit = framing == Framing::native ? 32 : 37;
        c.max_receive = 64;
        return c;
    }

    /** @brief Open a Card using production AES primitives and a strict scripted reader. */
    std::shared_ptr<managed::Card> connect(const std::shared_ptr<CardTransport>& transport) {
        auto crypto = openssl_provider();
        expect(static_cast<bool>(crypto), "OpenSSL provider");
        auto card = managed::Card::connect(transport, crypto.value());
        expect(static_cast<bool>(card), "managed card");
        return card.value();
    }

    /** @brief Exercise writes and reads at AES, APDU, AF and EV3 capacity boundaries. */
    void long_transfer(Framing framing, std::size_t size) {
        Bytes data(size);
        for (std::size_t index = 0; index < size; ++index) {
            data[index] = static_cast<Byte>((index * 17 + 3) % 256);
        }
        // Native file 1, offset 0, explicit little-endian byte count.
        Bytes header{1,
                     0,
                     0,
                     0,
                     static_cast<Byte>(size),
                     static_cast<Byte>(size >> 8),
                     static_cast<Byte>(size >> 16)};
        Bytes uploaded = header;
        uploaded.insert(uploaded.end(), data.begin(), data.end());
        std::deque<ReplayStep> steps;
        for (std::size_t offset = 0; offset < uploaded.size(); offset += 31) {
            const auto count = std::min<std::size_t>(31, uploaded.size() - offset);
            steps.push_back({request(framing, offset == 0 ? 0x3D : 0xAF,
                                     ByteView(uploaded).subspan(offset, count)),
                             response(framing, offset + count == uploaded.size() ? 0 : 0xAF)});
        }
        for (std::size_t offset = 0; offset < data.size(); offset += 23) {
            const auto count = std::min<std::size_t>(23, data.size() - offset);
            steps.push_back({request(framing, offset == 0 ? 0xBD : 0xAF,
                                     offset == 0 ? ByteView(header) : ByteView{}),
                             response(framing, offset + count == data.size() ? 0 : 0xAF,
                                      ByteView(data).subspan(offset, count))});
        }
        auto reader = std::make_shared<ReplayTransport>(std::move(steps), capabilities(framing));
        auto card = connect(reader);
        auto write = card->write_data(FileNumber::make(1).value(), Offset::make(0).value(), data,
                                      CommunicationMode::plain);
        expect(static_cast<bool>(write), "long upload succeeds with exact continuous AF frames");
        auto read = card->read_data(FileNumber::make(1).value(), Offset::make(0).value(),
                                    ByteCount::make(static_cast<uint32_t>(size)).value(),
                                    CommunicationMode::plain);
        expect(read && read.value() == data, "long read reconstructs original payload exactly");
        expect(reader->remaining() == 0, "no missing, duplicate or extraneous frame");
    }

    /** @brief Lost commit response is unknown, blocks subsequent I/O, and is never replayed. */
    void lost_commit(Framing framing) {
        auto reader = std::make_shared<ReplayTransport>(
            std::deque<ReplayStep>{
                {request(framing, 0xC7, {}),
                 Error{ErrorCode::timeout, "lost commit receipt", Outcome::unknown}}},
            capabilities(framing));
        auto card = connect(reader);
        auto result = card->commit_transaction();
        expect(!result && result.error().outcome == Outcome::unknown,
               "lost commit remains unknown");
        auto retry = card->commit_transaction();
        expect(!retry && retry.error().code == ErrorCode::session_invalid,
               "uncertain session blocks repeated commit");
        expect(reader->remaining() == 0, "commit transmitted only once");
    }

    /** @brief Fail each upload boundary and retain uncertainty for any previously delivered frame.
     */
    void interruption_boundaries(Framing framing) {
        Bytes data(120, 0x55);
        Bytes wire{2, 0, 0, 0, 120, 0, 0};
        wire.insert(wire.end(), data.begin(), data.end());
        for (std::size_t interrupted = 0; interrupted < 5; ++interrupted) {
            std::deque<ReplayStep> steps;
            for (std::size_t frame = 0; frame <= interrupted; ++frame) {
                const auto offset = frame * 31;
                const auto count = std::min<std::size_t>(31, wire.size() - offset);
                Result<Bytes> reply = response(framing, 0xAF);
                if (frame == interrupted) {
                    reply =
                        Error{ErrorCode::timeout, "injected frame interruption", Outcome::not_sent};
                }
                steps.push_back({request(framing, frame == 0 ? 0x3D : 0xAF,
                                         ByteView(wire).subspan(offset, count)),
                                 std::move(reply)});
            }
            auto reader =
                std::make_shared<ReplayTransport>(std::move(steps), capabilities(framing));
            auto card = connect(reader);
            auto write = card->write_data(FileNumber::make(2).value(), Offset::make(0).value(),
                                          data, CommunicationMode::plain);
            expect(!write, "interrupted write fails");
            expect(write.error().outcome ==
                       (interrupted == 0 ? Outcome::not_sent : Outcome::unknown),
                   "logical outcome includes earlier AF delivery");
            expect(reader->remaining() == 0, "no retry after AF interruption");
        }
    }

    /** @brief Two host threads cannot interleave their application-level AF sequences. */
    void concurrent_writes() {
        std::atomic<unsigned> commands{};
        std::atomic<unsigned> frames{};
        std::size_t remaining{};
        auto reader = std::make_shared<CallbackTransport>(
            capabilities(Framing::native),
            TransportCallbacks{
                .exchange = [&](ByteView frame, const ExchangeOptions&) -> Result<Bytes> {
                    ++frames;
                    if (frame[0] == 0x3D) {
                        expect(remaining == 0,
                               "new command starts only after prior AF chain completes");
                        ++commands;
                        remaining = 107;
                    } else {
                        expect(frame[0] == 0xAF && remaining != 0,
                               "continuation belongs to active command");
                    }
                    remaining -= frame.size() - 1;
                    std::this_thread::yield();
                    return Bytes{static_cast<Byte>(remaining ? 0xAF : 0)};
                },
                .cancel = {},
                .reset = {}});
        auto card = connect(reader);
        const auto operation = [&] {
            auto result = card->write_data(FileNumber::make(1).value(), Offset::make(0).value(),
                                           Bytes(100), CommunicationMode::plain);
            expect(static_cast<bool>(result), "serialized write");
        };
        std::thread first(operation), second(operation);
        first.join();
        second.join();
        expect(commands == 2 && frames == 8 && remaining == 0,
               "both complete writes delivered once");
    }

    /** @brief Verify a transaction validates file type then serializes staging through commit. */
    void transactional_batch() {
        auto reader = std::make_shared<ReplayTransport>(
            std::deque<ReplayStep>{{Bytes{0xF5, 1}, Bytes{0, 2, 0, 0xEE, 0xEE, 0, 0, 0, 0, 0x10,
                                                          0x27, 0, 0, 0, 0, 0, 0, 0}},
                                   {Bytes{0xDC, 1, 25, 0, 0, 0}, Bytes{0}},
                                   {Bytes{0xC7}, Bytes{0}}},
            capabilities(Framing::native));
        auto card = connect(reader);
        managed::TransactionPlan operations;
        auto mutation = debit(FileNumber::make(1).value(), 25, CommunicationMode::plain);
        expect(static_cast<bool>(mutation), "typed transaction mutation");
        expect(static_cast<bool>(operations.add(std::move(mutation.value()))),
               "transaction plan accepts value mutation");
        auto receipt = card->execute_transaction(operations);
        expect(receipt && receipt.value().empty() && reader->remaining() == 0,
               "verified value file debited and committed once");
        auto standard_reader = std::make_shared<ReplayTransport>(
            std::deque<ReplayStep>{{Bytes{0xF5, 1}, Bytes{0, 0, 0, 0xEE, 0xEE, 0x10, 0, 0}}},
            capabilities(Framing::native));
        auto standard = connect(standard_reader);
        managed::TransactionPlan writes;
        auto write_command = write_data(FileNumber::make(1).value(), Offset::make(0).value(),
                                        Bytes{1}, CommunicationMode::plain);
        expect(write_command && writes.add(std::move(write_command.value())),
               "transaction plan accepts backup-data mutation");
        auto invalid = standard->execute_transaction(writes);
        expect(!invalid && invalid.error().outcome == Outcome::not_sent &&
                   standard_reader->remaining() == 0,
               "nontransactional standard file rejected before mutation");
    }

    /** @brief C++ callbacks also reject recursive command entry without deadlocking. */
    void callback_reentry() {
        std::shared_ptr<managed::Card> card;
        auto reader = std::make_shared<CallbackTransport>(
            capabilities(Framing::native),
            TransportCallbacks{.exchange = [&](ByteView, const ExchangeOptions&) -> Result<Bytes> {
                                   auto nested = card->free_memory();
                                   expect(!nested && nested.error().code == ErrorCode::busy,
                                          "C++ callback reentry rejected");
                                   return Bytes{0, 1, 0, 0};
                               },
                               .cancel = {},
                               .reset = {}});
        card = connect(reader);
        auto result = card->free_memory();
        expect(result && result.value() == 1, "outer command survives rejected callback reentry");
    }

    /** @brief Verify cancel, successful reset, failed reset, and destruction lifecycle boundaries.
     */
    void lifecycle_boundaries() {
        std::atomic<unsigned> exchanges{};
        std::atomic<unsigned> cancellations{};
        std::atomic<unsigned> resets{};
        auto reader = std::make_shared<CallbackTransport>(
            capabilities(Framing::native),
            TransportCallbacks{
                .exchange = [&](ByteView frame, const ExchangeOptions&) -> Result<Bytes> {
                    ++exchanges;
                    expect(frame.size() == 1 && frame.front() == 0x6E,
                           "lifecycle fixture receives only FreeMem");
                    return Bytes{0, 1, 0, 0};
                },
                .cancel = [&] { ++cancellations; },
                .reset = [&]() -> Result<void> {
                    ++resets;
                    return {};
                }});
        auto card = connect(reader);
        card->cancel();
        expect(cancellations == 1 && exchanges == 0,
               "cancel reaches transport without starting card I/O");
        auto reset = card->reset();
        expect(reset && resets == 1 && exchanges == 0,
               "successful reset advances managed generation without a command frame");
        auto memory = card->free_memory();
        expect(memory && memory.value() == 1 && exchanges == 1,
               "successful reset leaves the managed Card usable");
        card.reset();
        expect(cancellations == 1 && resets == 1 && exchanges == 1,
               "Card destruction erases local state without reader I/O");

        std::atomic<unsigned> failed_exchanges{};
        auto failed_reader = std::make_shared<CallbackTransport>(
            capabilities(Framing::native),
            TransportCallbacks{.exchange = [&](ByteView, const ExchangeOptions&) -> Result<Bytes> {
                                   ++failed_exchanges;
                                   return Bytes{0, 1, 0, 0};
                               },
                               .cancel = {},
                               .reset = []() -> Result<void> {
                                   return Error{ErrorCode::transport, "injected reset failure",
                                                Outcome::unknown};
                               }});
        auto failed_card = connect(failed_reader);
        auto failed_reset = failed_card->reset();
        expect(!failed_reset && failed_reset.error().outcome == Outcome::unknown,
               "failed reset preserves its transport uncertainty");
        auto blocked = failed_card->free_memory();
        expect(!blocked && blocked.error().code == ErrorCode::session_invalid &&
                   blocked.error().outcome == Outcome::not_sent && failed_exchanges == 0,
               "failed reset keeps Card unusable and prevents later I/O");
    }

    /** @brief Prove cancel bypasses an active Card lock and preserves uncertain delivery evidence.
     */
    void concurrent_cancel() {
        std::mutex mutex;
        std::condition_variable changed;
        bool entered{};
        bool cancelled{};
        std::atomic<unsigned> exchanges{};
        std::atomic<unsigned> cancellations{};
        auto reader = std::make_shared<CallbackTransport>(
            capabilities(Framing::native),
            TransportCallbacks{
                .exchange = [&](ByteView frame, const ExchangeOptions&) -> Result<Bytes> {
                    ++exchanges;
                    expect(frame.size() == 1 && frame.front() == 0x6E,
                           "concurrent cancellation starts one FreeMem frame");
                    std::unique_lock lock(mutex);
                    entered = true;
                    changed.notify_all();
                    if (!changed.wait_for(lock, std::chrono::seconds(2),
                                          [&] { return cancelled; })) {
                        return Error{ErrorCode::timeout, "cancel callback did not arrive",
                                     Outcome::unknown};
                    }
                    return Error{ErrorCode::cancelled, "fixture cancelled after possible send",
                                 Outcome::unknown};
                },
                .cancel =
                    [&] {
                        ++cancellations;
                        {
                            std::lock_guard lock(mutex);
                            cancelled = true;
                        }
                        changed.notify_all();
                    },
                .reset = {}});
        auto card = connect(reader);
        std::optional<Result<std::uint32_t>> operation;
        std::thread worker([&] { operation.emplace(card->free_memory()); });
        {
            std::unique_lock lock(mutex);
            expect(changed.wait_for(lock, std::chrono::seconds(2), [&] { return entered; }),
                   "reader callback entered before concurrent cancel");
        }
        card->cancel();
        worker.join();
        expect(operation && !*operation && operation->error().code == ErrorCode::cancelled &&
                   operation->error().outcome == Outcome::unknown && exchanges == 1 &&
                   cancellations == 1,
               "concurrent cancel interrupts one attempt without weakening unknown outcome");
        auto blocked = card->free_memory();
        expect(!blocked && blocked.error().code == ErrorCode::session_invalid && exchanges == 1,
               "unknown cancelled delivery leaves managed Card unusable");
    }

} // namespace

/** @brief Run bounded and long workflow scenarios in both native envelope modes. */
int main() {
    constexpr std::array<std::size_t, 17> transfer_sizes{
        1, 15, 16, 17, 24, 25, 31, 32, 58, 59, 60, 61, 255, 256, 4096, 32768, 65536};
    for (const auto framing : {desfire::Framing::native, desfire::Framing::iso7816}) {
        for (const std::size_t size : transfer_sizes) {
            long_transfer(framing, size);
        }
        interruption_boundaries(framing);
        lost_commit(framing);
    }
    concurrent_writes();
    transactional_batch();
    callback_reentry();
    lifecycle_boundaries();
    concurrent_cancel();
    std::cout << "Long transfer and recovery scenarios passed\n";
}
