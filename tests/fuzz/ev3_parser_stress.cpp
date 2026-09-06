/** @file ev3_parser_stress.cpp
 * @brief Reproducible adversarial corpus runner for every binary parser.
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

/** @brief Invoke the same parser entry point used by the coverage-guided libFuzzer target. */
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

/** @brief Run boundary lengths, structured seeds and reproducible mutations under sanitizers. */
int main() {
    std::uint32_t state = 0xE3302026;
    const auto next = [&] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    const std::array<std::vector<std::uint8_t>, 7> seeds{
        {{},
         {0, 0, 0xEE, 0xEE, 0x20, 0, 0},
         {2, 3, 0xEE, 0xEE, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0, 1},
         {3, 0, 0xEE, 0xEE, 16, 0, 0, 10, 0, 0, 5, 0, 0},
         {5, 0, 0xEF, 0xEE, 2, 0},
         {4, 1, 1, 0x12, 0, 0x18, 5, 4, 1, 1, 0x12, 0, 0x18, 5,
          4, 1, 2, 3,    4, 5,    6, 1, 2, 3, 4,    5, 1,    0x26},
         {0, 0x91, 0xAF}}};
    for (const auto& seed : seeds) {
        (void)LLVMFuzzerTestOneInput(seed.data(), seed.size());
    }
    for (std::size_t iteration = 0; iteration < 100000; ++iteration) {
        std::vector<std::uint8_t> input;
        if ((iteration % 2) == 0) {
            input.resize(next() % 513);
            for (auto& byte : input) {
                byte = static_cast<std::uint8_t>(next());
            }
        } else {
            input = seeds[next() % seeds.size()];
            for (std::size_t mutation = 0; mutation < 1 + (next() % 8); ++mutation) {
                if (input.empty()) {
                    input.push_back(static_cast<std::uint8_t>(next()));
                } else {
                    input[next() % input.size()] ^= static_cast<std::uint8_t>(next());
                }
            }
            if (iteration % 3 == 0) {
                input.resize(next() % 129);
            }
        }
        (void)LLVMFuzzerTestOneInput(input.data(), input.size());
    }
    std::cout << "100000 seeded parser stress inputs passed\n";
}
