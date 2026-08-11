#!/usr/bin/env python3

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


CHECKER_PATH = Path(__file__).parents[2] / "scripts" / "check_alcp_exports.py"
SPEC = importlib.util.spec_from_file_location("check_alcp_exports", CHECKER_PATH)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

EXTRACTOR_PATH = Path(__file__).parents[2] / "scripts" / "extract_export_symbols.py"
EXTRACTOR_SPEC = importlib.util.spec_from_file_location(
    "extract_export_symbols", EXTRACTOR_PATH
)
assert EXTRACTOR_SPEC and EXTRACTOR_SPEC.loader
extractor = importlib.util.module_from_spec(EXTRACTOR_SPEC)
EXTRACTOR_SPEC.loader.exec_module(extractor)


class PatternTests(unittest.TestCase):
    def test_exact_and_prefix_patterns_are_anchored(self):
        symbol = "alcp::cipher::Cipher::encrypt(int)"

        self.assertTrue(checker.matches(symbol, symbol))
        self.assertFalse(checker.matches("alcp::cipher::Cipher", symbol))
        self.assertTrue(checker.matches("alcp::cipher::Cipher::*", symbol))
        self.assertFalse(checker.matches("cipher::Cipher::*", symbol))

    def test_embedded_alcp_namespace_does_not_match_foreign_owner(self):
        symbol = "foreign::wrapper<alcp::cipher::Cipher>::run()"

        self.assertFalse(checker.matches("alcp::cipher::Cipher*", symbol))
        self.assertFalse(
            checker.matches(
                "alcp::cipher::Cipher*",
                "evil(alcp::cipher::Cipher::encrypt())",
            )
        )

    def test_abi_prefixes_and_return_types_preserve_owner(self):
        self.assertTrue(
            checker.matches(
                "alcp::cipher::Cipher::*",
                "non-virtual thunk to alcp::cipher::Cipher::encrypt()",
            )
        )
        self.assertTrue(
            checker.matches(
                "alcp::cipher::Cipher::*",
                "unsigned long alcp::cipher::Cipher::encrypt()",
            )
        )
        self.assertTrue(
            checker.matches(
                "std::_Hashtable<unsigned short,*",
                "std::pair<int, bool> "
                "std::_Hashtable<unsigned short, int>::insert(int)",
            )
        )
        self.assertTrue(
            checker.matches(
                "__gnu_cxx::*",
                "decltype ((left.base())-(right.base())) "
                "__gnu_cxx::operator-(left, right)",
            )
        )


class DynamicSymbolTests(unittest.TestCase):
    def test_non_mangled_compiler_helper_keeps_raw_name(self):
        self.assertEqual(
            checker.demangle(["__cxa_call_terminate"]),
            {"__cxa_call_terminate": "__cxa_call_terminate"},
        )

    @mock.patch.object(subprocess, "check_output")
    def test_parser_keeps_weak_and_data_symbols(self, check_output):
        check_output.return_value = "\n".join(
            [
                "0000000000001000 T text_export",
                "0000000000002000 W weak_export",
                "0000000000003000 D data_export",
                "0000000000004000 V weak_object_export",
                "A absolute_export",
            ]
        )

        symbols = checker.dynamic_symbols(Path("plugin.so"))

        self.assertEqual(
            symbols,
            {
                "text_export": "T",
                "weak_export": "W",
                "data_export": "D",
                "weak_object_export": "V",
                "absolute_export": "A",
            },
        )
        check_output.assert_called_once_with(
            ["nm", "-D", "--defined-only", "plugin.so"], text=True
        )


class ExtractorTests(unittest.TestCase):
    def test_nested_if_zero_stays_disabled_until_matching_endif(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "exports.cc").write_text(
                "IPP_COMPAT_EXPORT active_before() {}\n"
                "#if 0\n"
                "#ifdef INNER\n"
                "IPP_COMPAT_EXPORT disabled_inner() {}\n"
                "#endif\n"
                "IPP_COMPAT_EXPORT disabled_after_inner() {}\n"
                "#endif\n"
                "IPP_COMPAT_EXPORT active_after() {}\n"
            )

            self.assertEqual(
                extractor.ipp_symbols(source),
                {"active_before", "active_after"},
            )

    def test_public_extractor_reads_annotated_alcp_declarations(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "api.h").write_text(
                "ALCP_API_EXPORT alc_error_t\n"
                "alcp_exported(void);\n"
                "alc_error_t alcp_unannotated(void);\n"
            )

            self.assertEqual(
                extractor.alcp_symbols(source),
                {"alcp_exported"},
            )


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.manifest = self.root / "exports.txt"
        self.manifest.write_text("required_export\nmissing_export\n")

    @mock.patch.object(checker, "demangle", return_value={})
    @mock.patch.object(
        checker,
        "dynamic_symbols",
        return_value={"required_export": "T", "unexpected_export": "T"},
    )
    def test_reports_required_missing_and_unexpected(self, _symbols, _demangle):
        errors = checker.validate(
            Path("plugin.so"), self.manifest, None, False, False
        )

        self.assertEqual(
            errors,
            [
                "missing C export: missing_export",
                "unexpected export: unexpected_export",
            ],
        )

    @mock.patch.object(checker, "demangle", return_value={})
    @mock.patch.object(
        checker,
        "dynamic_symbols",
        return_value={"required_export": "T", "unexpected_export": "T"},
    )
    def test_allow_unlisted_still_checks_required_exports(self, _symbols, _demangle):
        errors = checker.validate(
            Path("plugin.so"), self.manifest, None, True, False
        )

        self.assertEqual(errors, ["missing C export: missing_export"])

    @mock.patch.object(checker, "demangle", return_value={})
    @mock.patch.object(
        checker, "dynamic_symbols", return_value={"required_export": "T"}
    )
    def test_plain_manifest_needs_no_cpp_manifest(self, _symbols, _demangle):
        self.manifest.write_text("required_export\n")

        self.assertEqual(
            checker.validate(Path("plugin.so"), self.manifest, None, False, False),
            [],
        )

    @mock.patch.object(
        checker,
        "demangle",
        return_value={"__cxa_call_terminate": "__cxa_call_terminate"},
    )
    @mock.patch.object(
        checker,
        "dynamic_symbols",
        return_value={"required_export": "T", "__cxa_call_terminate": "T"},
    )
    def test_exact_raw_compiler_helper_can_be_allowed(self, _symbols, _demangle):
        self.manifest.write_text("required_export\n")
        cpp_manifest = self.root / "cpp.txt"
        cpp_manifest.write_text("allow __cxa_call_terminate\n")

        self.assertEqual(
            checker.validate(
                Path("plugin.so"), self.manifest, cpp_manifest, False, False
            ),
            [],
        )

    @mock.patch.object(
        checker,
        "demangle",
        return_value={
            "_ZSt4copy": "std::copy<unsigned char*>(unsigned char*, unsigned char*)"
        },
    )
    @mock.patch.object(
        checker,
        "dynamic_symbols",
        return_value={"required_export": "T", "_ZSt4copy": "W"},
    )
    def test_weak_standard_library_support_can_be_allowed(
        self, _symbols, _demangle
    ):
        self.manifest.write_text("required_export\n")
        cpp_manifest = self.root / "cpp.txt"
        cpp_manifest.write_text("allow-weak std::*\n")

        self.assertEqual(
            checker.validate(
                Path("plugin.so"), self.manifest, cpp_manifest, False, False
            ),
            [],
        )

    @mock.patch.object(
        checker,
        "demangle",
        return_value={"_ZSt4copy": "std::copy<unsigned char*>(unsigned char*)"},
    )
    @mock.patch.object(
        checker,
        "dynamic_symbols",
        return_value={"required_export": "T", "_ZSt4copy": "T"},
    )
    def test_strong_standard_library_export_is_still_rejected(
        self, _symbols, _demangle
    ):
        self.manifest.write_text("required_export\n")
        cpp_manifest = self.root / "cpp.txt"
        cpp_manifest.write_text("allow-weak std::*\n")

        self.assertEqual(
            checker.validate(
                Path("plugin.so"), self.manifest, cpp_manifest, False, False
            ),
            ["unexpected export: _ZSt4copy "
             "(std::copy<unsigned char*>(unsigned char*))"],
        )

    @mock.patch.object(
        checker,
        "demangle",
        return_value={"_ZSt4swapIh": "_ZSt4swapIh"},
    )
    @mock.patch.object(
        checker,
        "dynamic_symbols",
        return_value={"required_export": "T", "_ZSt4swapIh": "T"},
    )
    def test_undemangled_aocc_std_helper_can_be_allowed(
        self, _symbols, _demangle
    ):
        self.manifest.write_text("required_export\n")
        cpp_manifest = self.root / "cpp.txt"
        cpp_manifest.write_text("allow _ZSt*\n")

        self.assertEqual(
            checker.validate(
                Path("plugin.so"), self.manifest, cpp_manifest, False, False
            ),
            [],
        )

    @mock.patch.object(
        checker,
        "demangle",
        return_value={
            "_ZN9__gnu_cxxeq": (
                "bool __gnu_cxx::operator==<unsigned char const*, "
                "std::vector<unsigned char> >()"
            )
        },
    )
    @mock.patch.object(
        checker,
        "dynamic_symbols",
        return_value={"required_export": "T", "_ZN9__gnu_cxxeq": "T"},
    )
    def test_strong_aocc_gnu_helper_with_return_type_can_be_allowed(
        self, _symbols, _demangle
    ):
        self.manifest.write_text("required_export\n")
        cpp_manifest = self.root / "cpp.txt"
        cpp_manifest.write_text("allow __gnu_cxx::*\n")

        self.assertEqual(
            checker.validate(
                Path("plugin.so"), self.manifest, cpp_manifest, False, False
            ),
            [],
        )

    @mock.patch.object(
        checker,
        "demangle",
        return_value={"_ZN7foreignE": "foreign::alcp::Required::method()"},
    )
    @mock.patch.object(
        checker,
        "dynamic_symbols",
        return_value={"required_export": "T", "_ZN7foreignE": "T"},
    )
    def test_reports_missing_required_cpp_and_foreign_export(
        self, _symbols, _demangle
    ):
        self.manifest.write_text("required_export\n")
        cpp_manifest = self.root / "cpp.txt"
        cpp_manifest.write_text("required alcp::Required::*\n")

        errors = checker.validate(
            Path("plugin.so"), self.manifest, cpp_manifest, False, False
        )

        self.assertEqual(
            errors,
            [
                "missing required C++ export: alcp::Required::*",
                "unexpected export: _ZN7foreignE "
                "(foreign::alcp::Required::method())",
            ],
        )

    @mock.patch.object(checker, "validate", return_value=[])
    def test_manifest_cli_alias_does_not_require_cpp_manifest(self, validate):
        argv = [
            "check_alcp_exports.py",
            "--library",
            "plugin.so",
            "--manifest",
            str(self.manifest),
        ]

        with mock.patch.object(sys, "argv", argv):
            self.assertEqual(checker.main(), 0)

        validate.assert_called_once_with(
            Path("plugin.so"), self.manifest, None, False, False
        )


if __name__ == "__main__":
    unittest.main()
