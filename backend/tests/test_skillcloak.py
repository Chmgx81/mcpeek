"""Tests for SKILLCLOAK detection."""

import pytest

from app.services.skillcloak_detector import (
    _calculate_shannon_entropy,
    _find_decoder_patterns,
    _find_hidden_dirs,
    _find_manifest_abuse,
    _find_packing_patterns,
    detect_skillcloak,
)


class TestShannonEntropy:
    def test_empty_string(self):
        assert _calculate_shannon_entropy("") == 0.0

    def test_low_entropy_uniform(self):
        # All same character = 0 entropy
        assert _calculate_shannon_entropy("aaaa") == 0.0

    def test_high_entropy_random(self):
        # High entropy random string
        text = "aB3$xZ7!mK9@pQ2"
        entropy = _calculate_shannon_entropy(text)
        assert entropy > 3.0

    def test_base64_high_entropy(self):
        import base64
        data = b"This is a test payload with some data"
        b64 = base64.b64encode(data).decode()
        entropy = _calculate_shannon_entropy(b64)
        assert entropy > 4.0


class TestHiddenDirs:
    def test_detects_git(self):
        hits = _find_hidden_dirs("load from .git/config")
        assert len(hits) > 0

    def test_detects_node_modules(self):
        hits = _find_hidden_dirs("require('node_modules/pkg')")
        assert len(hits) > 0

    def test_detects_nested_hidden(self):
        hits = _find_hidden_dirs(".hidden/.another/path")
        assert len(hits) > 0

    def test_clean_content(self):
        hits = _find_hidden_dirs("normal config content")
        assert hits == []


class TestDecoderPatterns:
    def test_detects_atob(self):
        hits = _find_decoder_patterns("atob(encoded)")
        assert len(hits) > 0

    def test_detects_eval(self):
        hits = _find_decoder_patterns("eval(code)")
        assert len(hits) > 0

    def test_detects_child_process(self):
        hits = _find_decoder_patterns("child_process.spawn()")
        assert len(hits) > 0

    def test_detects_subprocess(self):
        hits = _find_decoder_patterns("subprocess.run(cmd)")
        assert len(hits) > 0

    def test_clean_content(self):
        hits = _find_decoder_patterns("normal code")
        assert hits == []


class TestPackingPatterns:
    def test_detects_self_extract(self):
        hits = _find_packing_patterns("self-extract the payload")
        assert len(hits) > 0

    def test_detects_hex_array(self):
        hits = _find_packing_patterns("0x41, 0x42, 0x43, 0x44, 0x45, 0x46")
        assert len(hits) > 0

    def test_detects_from_char_code(self):
        hits = _find_packing_patterns("String.fromCharCode(65, 66, 67)")
        assert len(hits) > 0

    def test_clean_content(self):
        hits = _find_packing_patterns("normal config")
        assert hits == []


class TestManifestAbuse:
    def test_detects_write_file(self):
        hits = _find_manifest_abuse("fs.writeFileSync(path, data)")
        assert len(hits) > 0

    def test_detects_mkdir(self):
        hits = _find_manifest_abuse("mkdirSync(dir)")
        assert len(hits) > 0

    def test_detects_chmod(self):
        hits = _find_manifest_abuse("chmod(0o755, path)")
        assert len(hits) > 0

    def test_clean_content(self):
        hits = _find_manifest_abuse("normal code")
        assert hits == []


class TestDetectSkillcloak:
    def test_empty_content(self):
        findings = detect_skillcloak("")
        assert findings == []

    def test_short_content(self):
        findings = detect_skillcloak("ab")
        assert findings == []

    def test_clean_config_no_findings(self):
        content = '{"name": "my-server", "version": "1.0.0"}'
        findings = detect_skillcloak(content, source="test")
        # Should not produce skillcloak findings for clean JSON
        skillcloak_findings = [f for f in findings if f.category == "skillcloak"]
        assert len(skillcloak_findings) == 0

    def test_high_entropy_detected(self):
        import random
        import string
        random.seed(42)
        content = "".join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=200))
        findings = detect_skillcloak(content, source="test")
        assert any("entropy" in f.title.lower() for f in findings)

    def test_decoder_pattern_detected(self):
        content = 'eval(atob("SGVsbG8="))'
        findings = detect_skillcloak(content, source="test")
        assert any("decoder" in f.title.lower() for f in findings)

    def test_hidden_dir_detected(self):
        content = "load from .git/HEAD"
        findings = detect_skillcloak(content, source="test")
        assert any("hidden" in f.title.lower() for f in findings)

    def test_manifest_abuse_detected(self):
        content = 'fs.writeFileSync("/tmp/payload", data)'
        findings = detect_skillcloak(content, source="test")
        assert any("file creation" in f.title.lower() for f in findings)
