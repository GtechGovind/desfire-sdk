# CLion formatting and documentation

The SDK uses Doxygen `/** ... */` blocks for C/C++ API documentation. These are
recognized directly by CLion; generating HTML is a separate, optional step.

## Read documentation in the editor

Place the caret on a documented symbol and invoke **Quick Documentation**. For an
in-editor rendered view, use **Render All Doc Comments** from the comment gutter's
context menu. These features are documented in JetBrains'
[Doxygen documentation guide](https://www.jetbrains.com/help/clion/creating-and-viewing-doxygen-documentation.html).

## Match repository formatting

In **Settings → Editor → Code Style → C/C++ → General**, select the **Clang-Format**
formatting engine, or enable **Read code style from .clang-format files** for the CLion
formatter. Then use **Code → Reformat Code**. The repository's `.clang-format` controls
namespace indentation, whitespace, access-specifier spacing, and line length. See the
[CLion ClangFormat guide](https://www.jetbrains.com/help/clion/clangformat-as-alternative-formatter.html).

The IDE settings file currently has its own user-maintained inspection and formatter
preferences. They are not silently replaced by the SDK's source formatting script.

## Write new API comments

Use a summary followed by the caller contract and relevant reasons:

```cpp
/**
 * @brief Borrow the successful payload without copying it.
 *
 * @return A read-only reference owned by this result.
 * @throws std::bad_variant_access If the result does not contain a value.
 * @warning The reference must not outlive this result.
 */
```

Use `@param` for actual named function parameters and `@tparam` for template
parameters. Explain returned `Result` errors under `@return`; use `@throws` only for
exceptions the function can actually throw. Document reference lifetimes, units,
state changes, and recovery behavior when relevant. Avoid describing a planned
feature as an existing guarantee.

`foundation/include/desfire/foundation/result.hpp` is the reference for this style.
Its value/error constructors intentionally permit conversion because native functions
return values and errors directly. Formatting must not change that API behavior.

Out-of-line definitions use a short copy block so both the header and implementation
remain navigable without maintaining two contracts:

```cpp
/** @copydoc Card::select_application */
Result<void> Card::select_application(ApplicationId id, const ExchangeOptions& options) {
    // Implementation comments explain protocol reasons rather than restating the call.
}
```

## Generate HTML separately

With Doxygen installed, build the CMake `docs` target. Output goes to the ignored
`build/documentation` directory. Restricted references under `docs/vendor/` are not
Doxygen inputs and must never be published with the generated API documentation.
