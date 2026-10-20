"""Tests for :mod:`miwear.protogen` — inferring ``.proto`` from payloads.

The assertions deliberately check *structure*, not exact text: comments and
whitespace are free to change, but every test here pins a property a
``protoc`` run would depend on (a field exists, with that number and type,
exactly once, inside the right message).
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

import pytest

from miwear import protogen
from miwear.protobuf import encode_field_bytes as enc_bytes
from miwear.protobuf import encode_field_varint as enc_varint
from miwear.protobuf import encode_varint

ROOT = pathlib.Path(__file__).resolve().parent.parent

_FIELD_RE = re.compile(
    r"^\s*(?P<label>repeated\s+)?(?P<type>[A-Za-z_][\w.]*)\s+"
    r"(?P<name>[A-Za-z_][\w]*)\s*=\s*(?P<number>\d+)\s*;\s*$")
_MESSAGE_RE = re.compile(r"^message\s+(?P<name>[A-Za-z_]\w*)\s*\{$")


def tag(number: int, wire: int) -> bytes:
    return encode_varint((number << 3) | wire)


def fixed32(number: int, value: int) -> bytes:
    return tag(number, 5) + struct.pack("<I", value)


def fixed64(number: int, value: int) -> bytes:
    return tag(number, 1) + struct.pack("<Q", value)


def parse_schema(text: str) -> dict[str, dict[int, dict]]:
    """Parse rendered ``.proto`` text into ``{message: {field_no: details}}``."""
    messages: dict[str, dict[int, dict]] = {}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        match = _MESSAGE_RE.match(stripped)
        if match:
            current = match.group("name")
            assert current not in messages, f"message {current} declared twice"
            messages[current] = {}
            continue
        if stripped == "}":
            current = None
            continue
        if current is None:
            continue
        field = _FIELD_RE.match(stripped)
        if field:
            number = int(field.group("number"))
            assert number not in messages[current], (
                f"field {number} declared twice in {current}")
            messages[current][number] = {
                "type": field.group("type"),
                "name": field.group("name"),
                "repeated": bool(field.group("label")),
            }
    return messages


# ---------------------------------------------------------------------------
# Strict payload validation
# ---------------------------------------------------------------------------

class TestParseMessage:
    def test_valid_payload(self):
        payload = enc_varint(1, 5) + enc_bytes(2, b"abc")
        fields = protogen.parse_message(payload)
        assert fields is not None
        assert [f.number for f in fields] == [1, 2]

    def test_empty_payload_rejected(self):
        assert protogen.parse_message(b"") is None

    def test_garbage_rejected(self):
        assert protogen.parse_message(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff") is None

    def test_field_zero_rejected(self):
        assert protogen.parse_message(b"\x00\x01") is None

    def test_overrun_rejected(self):
        assert protogen.parse_message(b"\x12\x05ab") is None

    def test_non_canonical_varint_rejected(self):
        """0x80 0x00 decodes to 0 but re-encodes as 0x00: not protobuf."""
        assert protogen.parse_message(b"\x08\x80\x00") is None

    def test_illegal_field_number_rejected(self):
        payload = tag((1 << 29), 0) + b"\x01"
        assert protogen.parse_message(payload) is None


# ---------------------------------------------------------------------------
# Scalar type inference
# ---------------------------------------------------------------------------

class TestScalarInference:
    def _types(self, payloads, **kwargs):
        text = protogen.generate(payloads, message_name="M", **kwargs)
        return parse_schema(text)

    def test_small_varint_is_int32(self):
        schema = self._types([enc_varint(1, 300)])
        assert schema["M"][1]["type"] == "int32"

    def test_big_varint_is_int64(self):
        schema = self._types([enc_varint(1, 1 << 40)])
        assert schema["M"][1]["type"] == "int64"

    def test_huge_varint_is_uint64(self):
        schema = self._types([enc_varint(1, (1 << 63) + 5)])
        assert schema["M"][1]["type"] == "uint64"

    def test_bool_requires_the_flag(self):
        assert self._types([enc_varint(1, 1)])["M"][1]["type"] == "int32"
        assert self._types([enc_varint(1, 1)], use_bools=True)["M"][1]["type"] == "bool"

    def test_bool_needs_every_sample_to_be_0_or_1(self):
        schema = self._types([enc_varint(1, 1), enc_varint(1, 2)], use_bools=True)
        assert schema["M"][1]["type"] == "int32"

    def test_fixed32(self):
        assert self._types([fixed32(1, 7)])["M"][1]["type"] == "fixed32"

    def test_fixed64(self):
        assert self._types([fixed64(1, 7)])["M"][1]["type"] == "fixed64"

    def test_utf8_is_string(self):
        schema = self._types([enc_bytes(1, "小米手环".encode())])
        assert schema["M"][1]["type"] == "string"

    def test_binary_is_bytes(self):
        schema = self._types([enc_bytes(1, b"\x00\xff\xfe\x01")])
        assert schema["M"][1]["type"] == "bytes"

    def test_empty_field_is_bytes(self):
        schema = self._types([enc_bytes(1, b"")])
        assert schema["M"][1]["type"] == "bytes"

    def test_one_binary_sample_kills_the_string_vote(self):
        schema = self._types([enc_bytes(1, b"hello"), enc_bytes(1, b"\x00\x01\x02")])
        assert schema["M"][1]["type"] == "bytes"


# ---------------------------------------------------------------------------
# Aggregation by field number
# ---------------------------------------------------------------------------

class TestAggregation:
    def test_field_seen_in_only_some_payloads(self):
        payloads = [enc_varint(1, 1), enc_varint(1, 2) + enc_varint(2, 3)]
        text = protogen.generate(payloads, message_name="M")
        schema = parse_schema(text)
        assert set(schema["M"]) == {1, 2}

    def test_sample_count_is_aggregated(self):
        payloads = [enc_varint(1, 1)] * 5 + [enc_varint(1, 2) + enc_varint(2, 3)]
        root = protogen.infer_schema(payloads, message_name="M")
        assert root.fields[1].samples == 6
        assert root.fields[2].samples == 1
        assert root.payloads == 6

    def test_disjoint_fields_are_merged(self):
        payloads = [enc_varint(1, 1), enc_varint(2, 2), enc_varint(3, 3)]
        schema = parse_schema(protogen.generate(payloads, message_name="M"))
        assert set(schema["M"]) == {1, 2, 3}

    def test_field_numbers_are_sorted(self):
        payload = enc_varint(9, 1) + enc_varint(2, 2) + enc_varint(5, 3)
        schema = parse_schema(protogen.generate([payload], message_name="M"))
        assert list(schema["M"]) == [2, 5, 9]

    def test_majority_wins_on_wire_conflict(self):
        payloads = [enc_varint(1, 1), enc_varint(1, 2), enc_bytes(1, b"xyz")]
        root = protogen.infer_schema(payloads, message_name="M")
        assert root.fields[1].wire == 0
        assert root.fields[1].conflicts == 1
        assert root.fields[1].type_name == "int32"

    def test_conflict_is_flagged_in_the_output(self):
        payloads = [enc_varint(1, 1), enc_bytes(1, b"xyz")]
        text = protogen.generate(payloads, message_name="M")
        assert "conflicting wire type" in text

    def test_repeated_detected_within_one_message(self):
        payload = enc_varint(1, 1) + enc_varint(1, 2) + enc_varint(2, 3)
        schema = parse_schema(protogen.generate([payload], message_name="M"))
        assert schema["M"][1]["repeated"] is True
        assert schema["M"][2]["repeated"] is False

    def test_repeated_across_payloads_is_not_repeated(self):
        payloads = [enc_varint(1, 1), enc_varint(1, 2)]
        schema = parse_schema(protogen.generate(payloads, message_name="M"))
        assert schema["M"][1]["repeated"] is False

    def test_duplicate_in_one_of_many_payloads_wins(self):
        payloads = [enc_varint(1, 5), enc_varint(1, 1) + enc_varint(1, 2)]
        schema = parse_schema(protogen.generate(payloads, message_name="M"))
        assert schema["M"][1]["repeated"] is True


# ---------------------------------------------------------------------------
# Nested message detection
# ---------------------------------------------------------------------------

class TestNestedMessages:
    def test_nested_message_is_detected(self):
        inner = enc_varint(1, 26) + enc_varint(2, 1)
        payload = enc_varint(1, 1) + enc_bytes(3, inner)
        text = protogen.generate([payload], message_name="Pyt")
        schema = parse_schema(text)
        assert schema["Pyt"][3]["type"] == "PytField3"
        assert set(schema["PytField3"]) == {1, 2}

    def test_recursion_goes_two_levels(self):
        level2 = enc_varint(1, 9)
        level1 = enc_bytes(2, level2)
        payload = enc_bytes(1, level1)
        schema = parse_schema(protogen.generate([payload], message_name="L0"))
        assert schema["L0"][1]["type"] == "L0Field1"
        assert schema["L0Field1"][2]["type"] == "L0Field1Field2"
        assert set(schema["L0Field1Field2"]) == {1}

    def test_max_depth_stops_recursion(self):
        level2 = enc_varint(1, 9)
        level1 = enc_bytes(2, level2)
        payload = enc_bytes(1, level1)
        schema = parse_schema(protogen.generate([payload], message_name="L0",
                                                max_depth=1))
        assert schema["L0"][1]["type"] == "L0Field1"
        assert schema["L0Field1"][2]["type"] == "bytes"
        assert "L0Field1Field2" not in schema

    def test_zero_depth_keeps_everything_flat(self):
        payload = enc_bytes(1, enc_varint(1, 1))
        schema = parse_schema(protogen.generate([payload], message_name="L0",
                                                max_depth=0))
        assert schema["L0"][1]["type"] == "bytes"

    def test_printable_bytes_beat_nested_message(self):
        """A payload that is valid UTF-8 stays a string even if it parses."""
        inner = b"AB"                     # printable; b"\x08\x01" is not
        assert protogen.is_printable_text(inner)
        schema = parse_schema(protogen.generate([enc_bytes(1, inner)],
                                                message_name="M"))
        assert schema["M"][1]["type"] == "string"

    def test_non_printable_bytes_become_a_message(self):
        inner = enc_varint(1, 1)
        assert protogen.parse_message(inner) is not None
        assert not protogen.is_printable_text(inner)
        schema = parse_schema(protogen.generate([enc_bytes(1, inner)],
                                                message_name="M"))
        assert schema["M"][1]["type"] == "MField1"

    def test_one_non_message_sample_prevents_nesting(self):
        inner = enc_varint(1, 1)
        payloads = [enc_bytes(1, inner), enc_bytes(1, b"\xff\xff")]
        schema = parse_schema(protogen.generate(payloads, message_name="M"))
        assert schema["M"][1]["type"] == "bytes"

    def test_identical_messages_are_deduplicated(self):
        inner = enc_varint(1, 5) + enc_varint(2, 6)
        payload = enc_bytes(1, inner) + enc_bytes(2, inner)
        text = protogen.generate([payload], message_name="D")
        schema = parse_schema(text)
        assert schema["D"][1]["type"] == schema["D"][2]["type"]
        assert len(schema) == 2

    def test_self_similar_shape_terminates(self):
        """A message containing a message shaped like itself must not loop."""
        inner = enc_varint(1, 1)
        payload = enc_bytes(1, inner)
        text = protogen.generate([payload] * 2, message_name="S", max_depth=12)
        assert text.count("message ") == 2

    def test_child_names_are_prefixed_with_the_parent(self):
        schema = parse_schema(protogen.generate(
            [enc_bytes(1, enc_varint(1, 1))], message_name="Root"))
        assert "RootField1" in schema


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

class TestNaming:
    def test_default_field_names_are_synthetic(self):
        schema = parse_schema(protogen.generate([enc_varint(7, 1)],
                                                message_name="M"))
        assert schema["M"][7]["name"] == "field_7"

    def test_message_name_is_verbatim_when_legal(self):
        text = protogen.generate([enc_varint(1, 1)], message_name="pyt")
        assert "message Pyt {" in text

    def test_message_name_is_sanitised(self):
        text = protogen.generate([enc_varint(1, 1)], message_name="my msg-2")
        assert "message MyMsg2 {" in text

    def test_message_name_starting_with_a_digit_gets_a_prefix(self):
        text = protogen.generate([enc_varint(1, 1)], message_name="2fast")
        assert re.search(r"message M2fast \{", text)

    def test_name_hints_rename_fields(self):
        hints = {"M.1": "user_id", "M.2": "nickname"}
        payload = enc_varint(1, 5) + enc_bytes(2, b"bob")
        text = protogen.generate([payload], message_name="M", name_hints=hints)
        schema = parse_schema(text)
        assert schema["M"][1]["name"] == "user_id"
        assert schema["M"][2]["name"] == "nickname"

    def test_wildcard_hint_applies(self):
        payload = enc_varint(1, 5) + enc_bytes(9, enc_varint(2, 6))
        text = protogen.generate([payload], message_name="M",
                                 name_hints={"*.2": "value"})
        assert "value = 2;" in text

    def test_hint_names_are_snake_cased(self):
        text = protogen.generate([enc_varint(1, 5)], message_name="M",
                                 name_hints={"M.1": "UserID Number"})
        assert "user_id_number = 1;" in text

    def test_snake_case_helper(self):
        assert protogen._snake("UserID") == "user_id"
        assert protogen._snake("HTTPServer") == "http_server"
        assert protogen._snake("random_app") == "random_app"
        assert protogen._snake("a b:c") == "a_b_c"
        assert protogen._snake("") == "field"
        assert protogen._snake("2fast") == "_2fast"

    def test_name_hint_can_name_a_child_message(self):
        payload = enc_bytes(3, enc_varint(1, 1))
        text = protogen.generate([payload], message_name="M",
                                 name_hints={"M.3": "body"})
        assert "message Body {" in text

    def test_illegal_characters_are_replaced(self):
        text = protogen.generate([enc_varint(1, 1)], message_name="M",
                                 name_hints={"M.1": "a b:c"})
        assert "a_b_c = 1;" in text


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class TestRendering:
    def test_has_syntax_line_first(self):
        text = protogen.generate([enc_varint(1, 1)])
        body = [line for line in text.splitlines()
                if line and not line.startswith("//")]
        assert body[0] == 'syntax = "proto3";'

    def test_package_is_emitted(self):
        text = protogen.generate([enc_varint(1, 1)], package="acme.band")
        assert "package acme.band;" in text

    def test_package_can_be_omitted(self):
        text = protogen.generate([enc_varint(1, 1)], package=None)
        assert "package " not in text

    def test_header_comment_is_included(self):
        text = protogen.generate([enc_varint(1, 1)], header="from btsnoop\nrun 2")
        assert "// from btsnoop" in text
        assert "// run 2" in text

    def test_payload_count_is_reported(self):
        text = protogen.generate([enc_varint(1, 1)] * 3)
        assert "3 payload(s)" in text

    def test_output_ends_with_a_single_newline(self):
        text = protogen.generate([enc_varint(1, 1)])
        assert text.endswith("}\n")
        assert not text.endswith("\n\n")

    def test_reserved_field_number_is_flagged(self):
        text = protogen.generate([enc_varint(19500, 1)], message_name="M")
        assert "RESERVED" in text

    def test_every_brace_is_balanced(self):
        payload = enc_bytes(1, enc_varint(1, 1) + enc_bytes(2, enc_varint(2, 2)))
        text = protogen.generate([payload] * 2, message_name="M")
        assert text.count("{") == text.count("}")
        assert text.count('"') % 2 == 0

    def test_schema_to_dict(self):
        payload = enc_varint(1, 5) + enc_bytes(2, b"hi")
        data = protogen.schema_to_dict(
            protogen.infer_schema([payload], message_name="M"))
        assert data["payloads"] == 1
        assert data["messages"][0]["name"] == "M"
        first = data["messages"][0]["fields"][0]
        assert first["number"] == 1
        assert first["type"] == "int32"
        assert first["nested"] is False

    def test_schema_to_dict_is_json_serialisable(self):
        payload = enc_bytes(3, enc_varint(1, 1))
        data = protogen.schema_to_dict(
            protogen.infer_schema([payload], message_name="M"))
        assert json.loads(json.dumps(data))["messages"][0]["fields"][0]["nested"]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class TestErrors:
    def test_no_payloads(self):
        with pytest.raises(protogen.ProtoGenError):
            protogen.infer_schema([])

    def test_invalid_payload_names_the_index(self):
        try:
            protogen.infer_schema([enc_varint(1, 1), b"\x00\x01"])
        except protogen.ProtoGenError as exc:
            message = str(exc)
        else:
            raise AssertionError("invalid payload should have been rejected")
        assert "#1" in message

    def test_generate_propagates(self):
        with pytest.raises(protogen.ProtoGenError):
            protogen.generate([b"\xff\xff"])


# ---------------------------------------------------------------------------
# Input plumbing
# ---------------------------------------------------------------------------

class TestParseHex:
    def test_plain_hex(self):
        assert protogen.parse_hex("0801") == b"\x08\x01"

    def test_whitespace_colons_dashes_and_0x(self):
        assert protogen.parse_hex(" 0x08:01-0A ") == b"\x08\x01\x0a"
        assert protogen.parse_hex("08\n01\t0a") == b"\x08\x01\x0a"

    def test_odd_length_rejected(self):
        with pytest.raises(protogen.ProtoGenError):
            protogen.parse_hex("080")

    def test_non_hex_rejected(self):
        with pytest.raises(protogen.ProtoGenError):
            protogen.parse_hex("zzzz")

    def test_empty_rejected(self):
        with pytest.raises(protogen.ProtoGenError):
            protogen.parse_hex("   ")


class TestLoadPayloads:
    def test_literal_hex_arguments(self):
        assert protogen.load_payloads(["0801", "1005"]) == [b"\x08\x01", b"\x10\x05"]

    def test_file_of_hex_lines(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        try:
            path = tmp / "payloads.hex"
            path.write_text("# comment\n0801\n\n1005\n// also a comment\n",
                            encoding="utf-8")
            assert protogen.load_payloads([str(path)]) == [b"\x08\x01", b"\x10\x05"]
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_bad_line_in_file_reports_line_number(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        try:
            path = tmp / "bad.hex"
            path.write_text("0801\nzz\n", encoding="utf-8")
            try:
                protogen.load_payloads([str(path)])
            except protogen.ProtoGenError as exc:
                message = str(exc)
            else:
                raise AssertionError("a bad hex line should have been rejected")
            assert ":2:" in message
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_unreadable_source_is_a_clear_error(self):
        with pytest.raises(protogen.ProtoGenError):
            protogen.load_payloads(["not-a-file-and-not-hex"])


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

class TestCommandLine:
    def _tmpdir(self):
        return pathlib.Path(tempfile.mkdtemp())

    def _capture(self, argv, stdin_text=None):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        old_stdin = sys.stdin
        if stdin_text is not None:
            sys.stdin = io.StringIO(stdin_text)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = protogen.main(argv)
        finally:
            sys.stdin = old_stdin
        return code, out.getvalue(), err.getvalue()

    def test_hex_arguments_to_stdout(self):
        code, out, _err = self._capture(["08011005", "--name", "Demo"])
        assert code == 0
        assert "message Demo" in out
        assert 'syntax = "proto3";' in out

    def test_writes_to_file(self):
        tmp = self._tmpdir()
        try:
            target = tmp / "out.proto"
            code, out, err = self._capture(["0801", "-o", str(target)])
            assert code == 0
            assert out == ""
            assert "wrote" in err
            assert target.read_text(encoding="utf-8").startswith("// Generated")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_reads_a_file(self):
        tmp = self._tmpdir()
        try:
            path = tmp / "p.hex"
            path.write_text("0801\n1005\n", encoding="utf-8")
            code, out, _err = self._capture([str(path), "--name", "F"])
            assert code == 0
            assert "int32 field_2 = 2;" in out
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_reads_stdin(self):
        code, out, _err = self._capture(["-", "--name", "S"], stdin_text="0801\n")
        assert code == 0
        assert "message S" in out

    def test_json_mode(self):
        code, out, _err = self._capture(["08011005", "--json"])
        assert code == 0
        data = json.loads(out)
        assert data["messages"][0]["fields"][0]["type"] == "int32"

    def test_skips_invalid_payloads_with_a_warning(self):
        """A file may hold lines that are hex but not valid protobuf."""
        tmp = self._tmpdir()
        try:
            path = tmp / "mixed.hex"
            path.write_text("0801\nffffffffffffffffffffffff\n", encoding="utf-8")
            code, out, err = self._capture([str(path)])
            assert code == 0
            assert "message Payload" in out
            assert "warning" in err
            assert "skipped" in err
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_strict_mode_fails_on_invalid_payload(self):
        tmp = self._tmpdir()
        try:
            path = tmp / "mixed.hex"
            path.write_text("0801\nffffffffffffffffffffffff\n", encoding="utf-8")
            code, out, err = self._capture([str(path), "--strict"])
            assert code == 2
            assert out == ""
            assert "warning" in err
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_unparseable_argument_is_rejected_before_output(self):
        code, out, err = self._capture(["0801", "zzzz"])
        assert code == 2
        assert out == ""
        assert "hex payload" in err

    def test_no_payloads_is_an_error(self):
        tmp = self._tmpdir()
        try:
            path = tmp / "comments.hex"
            path.write_text("# only comments\n\n// nothing here\n", encoding="utf-8")
            code, _out, err = self._capture([str(path)])
            assert code == 2
            assert "no payloads" in err
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_names_file(self):
        tmp = self._tmpdir()
        try:
            hints = tmp / "names.json"
            hints.write_text(json.dumps({"Payload.1": "magic"}), encoding="utf-8")
            code, out, _err = self._capture(["0801", "--names", str(hints)])
            assert code == 0
            assert "int32 magic = 1;" in out
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_missing_names_file(self):
        code, _out, err = self._capture(["0801", "--names", "no-such-file.json"])
        assert code == 2
        assert "cannot read" in err

    def test_names_file_must_be_an_object(self):
        tmp = self._tmpdir()
        try:
            hints = tmp / "names.json"
            hints.write_text("[1, 2, 3]", encoding="utf-8")
            code, _out, err = self._capture(["0801", "--names", str(hints)])
            assert code == 2
            assert "JSON object" in err
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_package_can_be_cleared(self):
        code, out, _err = self._capture(["0801", "--package", ""])
        assert code == 0
        assert "package " not in out

    def test_main_is_exposed_for_the_lead_to_wire_in(self):
        assert callable(protogen.main)
        assert protogen.main.__module__ == "miwear.protogen"

    def test_module_runs_as_script(self):
        proc = subprocess.run([sys.executable, "-m", "miwear.protogen", "08011005",
                               "--name", "S"], cwd=str(ROOT),
                              capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        assert "message S" in proc.stdout


# ---------------------------------------------------------------------------
# End to end: capture-shaped payloads
# ---------------------------------------------------------------------------

class TestRealisticCapture:
    def _auth_verify(self, user_id: str = b"userid", cmd: int = 5) -> bytes:
        # Pyt{type=1, cmd=<cmd>, va0{f7=userId}}
        va0 = enc_bytes(7, user_id)
        return enc_varint(1, 1) + enc_varint(2, cmd) + enc_bytes(3, va0)

    def _v2_verify(self, random_app: bytes) -> bytes:
        # Pyt{type=1, cmd=26, va0{f30=Bb0{f1=randomApp}}}
        bb0 = enc_bytes(1, random_app)
        va0 = enc_bytes(30, bb0)
        return enc_varint(1, 1) + enc_varint(2, 26) + enc_bytes(3, va0)

    def test_pyt_shape_is_recovered(self):
        payloads = [self._auth_verify(b"a"), self._auth_verify(b"bob"),
                    self._v2_verify(bytes(range(16)))]
        text = protogen.generate(payloads, message_name="Pyt", max_depth=4)
        schema = parse_schema(text)
        root = schema["Pyt"]
        assert root[1]["type"] == "int32"
        assert root[2]["type"] == "int32"
        assert not root[3]["type"] in ("bytes", "string")
        assert 30 in schema[root[3]["type"]]

    def test_sample_counter_matches_the_batch(self):
        payloads = [self._auth_verify(b"x")] * 7
        root = protogen.infer_schema(payloads, message_name="Pyt", max_depth=3)
        assert root.payloads == 7
        assert root.fields[1].samples == 7
        assert root.fields[2].samples == 7

    def test_generated_schema_is_stable_across_runs(self):
        payloads = [self._auth_verify(b"a"), self._v2_verify(bytes(16))]
        first = protogen.generate(payloads, message_name="Pyt")
        second = protogen.generate(payloads, message_name="Pyt")
        assert first == second

    def test_batch_order_does_not_matter(self):
        a = self._auth_verify(b"a")
        b = self._v2_verify(bytes(range(16)))
        assert (protogen.generate([a, b], message_name="Pyt")
                == protogen.generate([b, a], message_name="Pyt"))
