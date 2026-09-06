/**
 * @file cpp17_throwing_test.cpp
 * @brief Verify the separately included opt-in C++17 throwing adapter.
 */
#include <desfire/cpp17/throwing.hpp>

#include <cstdint>
#include <iostream>
#include <utility>

/** @brief Throw and catch one structured facade error without involving card I/O. */
int main() {
    using namespace desfire::cpp17;
    auto failure = Result<std::uint32_t>::failure(
        {ErrorCode::busy, Outcome::not_sent, 0, "injected adapter failure"});
    try {
        static_cast<void>(throwing::value_or_throw(std::move(failure)));
    } catch (const throwing::ErrorException& exception) {
        if (exception.error().code == ErrorCode::busy &&
            exception.error().outcome == Outcome::not_sent) {
            std::cout << "C++17 throwing adapter passed\n";
            return 0;
        }
    }
    return 1;
}
