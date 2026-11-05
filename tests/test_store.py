"""Store tests — crypto, format, permissions. No Hermes runtime required."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from sealed_store import (
    KEY_BYTES,
    MAGIC,
    SealedError,
    WrongKey,
    decrypt,
    dump_dotenv,
    encrypt,
    file_mode,
    generate_key,
    inspect,
    mode_is_private,
    parse_dotenv,
    read_key,
    read_store,
    remove_entry,
    replace_entry,
    write_key,
    write_store,
)


def test_encrypt_roundtrip():
    key = generate_key()
    blob = encrypt(key, "OPENAI_API_KEY=sk-test\n")
    assert blob.startswith(MAGIC)
    assert decrypt(key, blob) == "OPENAI_API_KEY=sk-test\n"


def test_ciphertext_is_not_plaintext():
    key = generate_key()
    blob = encrypt(key, "SECRET=hunter2")
    assert b"hunter2" not in blob


def test_nonce_is_unique_per_write():
    key = generate_key()
    assert encrypt(key, "A=1") != encrypt(key, "A=1")


def test_wrong_key_fails_closed():
    blob = encrypt(generate_key(), "A=1")
    with pytest.raises(WrongKey):
        decrypt(generate_key(), blob)


def test_tampering_is_detected():
    import base64

    key = generate_key()
    blob = encrypt(key, "A=1")
    raw = bytearray(base64.urlsafe_b64decode(blob[len(MAGIC):]))
    raw[-1] ^= 0x01  # flip a ciphertext bit, leaving base64 valid
    tampered = MAGIC + base64.urlsafe_b64encode(bytes(raw))
    with pytest.raises(WrongKey):
        decrypt(key, tampered)


def test_garbage_payload_fails_closed():
    key = generate_key()
    with pytest.raises(SealedError):
        decrypt(key, MAGIC + b"not base64!!")


def test_bad_magic_rejected():
    with pytest.raises(SealedError):
        decrypt(generate_key(), b"PLAIN1\nwhatever")


def test_wrong_key_size_rejected():
    with pytest.raises(SealedError):
        encrypt(b"short", "A=1")


def test_key_file_is_private_and_never_overwritten(tmp_path):
    path = tmp_path / "sealed.key"
    write_key(path)
    assert file_mode(path) == 0o600
    with pytest.raises(FileExistsError):
        write_key(path)


def test_read_key_rejects_wrong_length(tmp_path):
    path = tmp_path / "bad.key"
    path.write_bytes(b"too short")
    with pytest.raises(SealedError):
        read_key(path)


def test_store_roundtrip_and_permissions(tmp_path):
    key = generate_key()
    path = tmp_path / "sealed.store"
    write_store(path, key, {"A": "1", "B": "two words"})
    assert file_mode(path) == 0o600
    assert read_store(path, key) == {"A": "1", "B": "two words"}


def test_store_replaces_atomically(tmp_path):
    key = generate_key()
    path = tmp_path / "sealed.store"
    write_store(path, key, {"A": "1"})
    write_store(path, key, {"A": "2"})
    assert read_store(path, key) == {"A": "2"}
    assert not list(tmp_path.glob(".*.tmp"))


def test_parse_dotenv_forms():
    text = """
# comment
export OPENAI_API_KEY=sk-123
QUOTED="two words"
SINGLE='keep $literal'
ESCAPED="line\\nbreak"
EMPTY=
invalid line without equals
9BAD=value
"""
    values = parse_dotenv(text)
    assert values["OPENAI_API_KEY"] == "sk-123"
    assert values["QUOTED"] == "two words"
    assert values["SINGLE"] == "keep $literal"
    assert values["ESCAPED"] == "line\nbreak"
    assert values["EMPTY"] == ""
    assert "9BAD" not in values


def test_dump_dotenv_roundtrips_awkward_values():
    values = {"PLAIN": "abc", "SPACED": "two words", "HASH": "a#b", "QUOTE": 'say "hi"', "NL": "a\nb"}
    assert parse_dotenv(dump_dotenv(values)) == values


def test_replace_and_remove():
    values = {"A": "1"}
    assert replace_entry(values, "B", "2") == {"A": "1", "B": "2"}
    assert remove_entry(values, "A") == {}
    with pytest.raises(SealedError):
        replace_entry(values, "bad name", "x")


def test_inspect_reports_open_permissions(tmp_path):
    key = generate_key()
    path = tmp_path / "sealed.store"
    write_store(path, key, {"A": "1"})
    assert inspect(path).problem == ""
    assert mode_is_private(file_mode(path))
    os.chmod(path, 0o644)
    info = inspect(path)
    assert "too open" in info.problem
    assert not mode_is_private(info.mode)


def test_missing_store_reports_problem(tmp_path):
    info = inspect(tmp_path / "nope.store")
    assert info.exists is False
    assert "does not exist" in info.problem
