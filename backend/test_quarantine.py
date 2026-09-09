from __future__ import annotations

import os
import tempfile
from pathlib import Path
import unittest

from werkzeug.datastructures import FileStorage
from quarantine import (
    SignatureScanner, isolate_upload, QuarantineError,
    _normalise_extension, _normalise_mime,
)


def _make_file(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)
    return path


MP4_MAGIC = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 20
MOV_MAGIC = b"\x00\x00\x00\x18ftypqt  " + b"\x00" * 20
WEBM_MAGIC = b"\x1a\x45\xdf\xa3\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 16
AVI_MAGIC = b"RIFF\x00\x00\x00\x00AVI " + b"\x00" * 20
MKV_MAGIC = b"\x1a\x45\xdf\xa3\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 16
_3GP_MAGIC = b"\x00\x00\x00\x18ftyp3gp4" + b"\x00" * 20
PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
GIF_MAGIC = b"GIF89a" + b"\x00" * 26


class TestNormaliseExtension(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_normalise_extension("video.mp4"), ".mp4")
    def test_none(self):
        self.assertIsNone(_normalise_extension("video"))
    def test_dot(self):
        self.assertIsNone(_normalise_extension("video."))
    def test_multi(self):
        self.assertEqual(_normalise_extension("my.video.mp4"), ".mp4")
    def test_case(self):
        self.assertEqual(_normalise_extension("VIDEO.MP4"), ".mp4")


class TestNormaliseMime(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_normalise_mime("video/mp4"), "video/mp4")
    def test_params(self):
        self.assertEqual(_normalise_mime("video/mp4; charset=utf-8"), "video/mp4")
    def test_none(self):
        self.assertIsNone(_normalise_mime(None))
    def test_empty(self):
        self.assertIsNone(_normalise_mime(""))


class TestSignatureScanner(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_detect_mp4(self):
        p = _make_file(self.tmp_path, "t.mp4", MP4_MAGIC)
        self.assertEqual(SignatureScanner.detect_format(p), "MP4")
    def test_detect_mov(self):
        p = _make_file(self.tmp_path, "t.mov", MOV_MAGIC)
        self.assertEqual(SignatureScanner.detect_format(p), "MOV")
    def test_detect_webm(self):
        p = _make_file(self.tmp_path, "t.webm", WEBM_MAGIC)
        self.assertEqual(SignatureScanner.detect_format(p), "Matroska")
    def test_detect_avi(self):
        p = _make_file(self.tmp_path, "t.avi", AVI_MAGIC)
        self.assertEqual(SignatureScanner.detect_format(p), "AVI")
    def test_detect_mkv(self):
        p = _make_file(self.tmp_path, "t.mkv", MKV_MAGIC)
        self.assertEqual(SignatureScanner.detect_format(p), "Matroska")
    def test_detect_3gp(self):
        p = _make_file(self.tmp_path, "t.3gp", _3GP_MAGIC)
        self.assertEqual(SignatureScanner.detect_format(p), "3GP")
    def test_detect_invalid(self):
        p = _make_file(self.tmp_path, "t.txt", b"plain text")
        self.assertIsNone(SignatureScanner.detect_format(p))
    def test_detect_empty(self):
        p = _make_file(self.tmp_path, "t.bin", b"")
        self.assertIsNone(SignatureScanner.detect_format(p))
    def test_detect_small(self):
        p = _make_file(self.tmp_path, "t.bin", b"\x00" * 5)
        self.assertIsNone(SignatureScanner.detect_format(p))

    def test_is_valid_true_mp4(self):
        p = _make_file(self.tmp_path, "t.mp4", MP4_MAGIC)
        self.assertTrue(SignatureScanner.is_valid_video(p))
    def test_is_valid_true_webm(self):
        p = _make_file(self.tmp_path, "t.webm", WEBM_MAGIC)
        self.assertTrue(SignatureScanner.is_valid_video(p))
    def test_is_valid_false(self):
        p = _make_file(self.tmp_path, "t.txt", b"not a video")
        self.assertFalse(SignatureScanner.is_valid_video(p))

    def test_consistency_mp4_ok(self):
        p = _make_file(self.tmp_path, "t.mp4", MP4_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mp4", content_type="video/mp4")
        self.assertTrue(v); self.assertIsNone(e)
    def test_consistency_webm_ok(self):
        p = _make_file(self.tmp_path, "t.webm", WEBM_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.webm", content_type="video/webm")
        self.assertTrue(v); self.assertIsNone(e)
    def test_consistency_mov_ok(self):
        p = _make_file(self.tmp_path, "t.mov", MOV_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mov", content_type="video/quicktime")
        self.assertTrue(v); self.assertIsNone(e)
    def test_consistency_avi_ok(self):
        p = _make_file(self.tmp_path, "t.avi", AVI_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.avi", content_type="video/x-msvideo")
        self.assertTrue(v); self.assertIsNone(e)
    def test_consistency_3gp_ok(self):
        p = _make_file(self.tmp_path, "t.3gp", _3GP_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.3gp", content_type="video/3gpp")
        self.assertTrue(v); self.assertIsNone(e)
    def test_consistency_mkv_ok(self):
        p = _make_file(self.tmp_path, "t.mkv", MKV_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mkv", content_type="video/x-matroska")
        self.assertTrue(v); self.assertIsNone(e)
    def test_consistency_octet_stream(self):
        p = _make_file(self.tmp_path, "t.mp4", MP4_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mp4", content_type="application/octet-stream")
        self.assertTrue(v); self.assertIsNone(e)
    def test_consistency_no_context(self):
        p = _make_file(self.tmp_path, "t.mp4", MP4_MAGIC)
        v, e = SignatureScanner.verify_consistency(p)
        self.assertTrue(v); self.assertIsNone(e)

    def test_consistency_png_spoof(self):
        p = _make_file(self.tmp_path, "m.mp4", PNG_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="m.mp4", content_type="video/mp4")
        self.assertFalse(v); self.assertIn("failed signature scan", e)
    def test_consistency_gif_spoof(self):
        p = _make_file(self.tmp_path, "f.mov", GIF_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="f.mov", content_type="video/quicktime")
        self.assertFalse(v); self.assertIn("failed signature scan", e)
    def test_consistency_wrong_ext(self):
        p = _make_file(self.tmp_path, "v.png", MP4_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.png", content_type="image/png")
        self.assertFalse(v); self.assertIn("unsupported extension", e)
    def test_consistency_wrong_mime(self):
        p = _make_file(self.tmp_path, "v.mp4", MP4_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mp4", content_type="image/png")
        self.assertFalse(v); self.assertIn("unsupported content type", e)
    def test_consistency_mime_mismatch(self):
        p = _make_file(self.tmp_path, "v.mp4", MP4_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mp4", content_type="video/webm")
        self.assertFalse(v); self.assertIn("signature matches", e)
    def test_consistency_ext_mismatch(self):
        p = _make_file(self.tmp_path, "v.mp4", AVI_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mp4", content_type="video/mp4")
        self.assertFalse(v); self.assertIn("signature matches", e)
    def test_consistency_mov_as_mp4(self):
        p = _make_file(self.tmp_path, "v.mp4", MOV_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mp4", content_type="video/mp4")
        self.assertFalse(v); self.assertIn("possible content-type spoofing", e)
    def test_consistency_3gp_as_mp4(self):
        p = _make_file(self.tmp_path, "v.mp4", _3GP_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mp4", content_type="video/mp4")
        self.assertFalse(v); self.assertIn("possible content-type spoofing", e)
    def test_consistency_webm_mkv_interchange(self):
        p = _make_file(self.tmp_path, "v.mkv", WEBM_MAGIC)
        v, e = SignatureScanner.verify_consistency(p, filename="v.mkv", content_type="video/x-matroska")
        self.assertTrue(v); self.assertIsNone(e)
        p2 = _make_file(self.tmp_path, "v.webm", MKV_MAGIC)
        v2, e2 = SignatureScanner.verify_consistency(p2, filename="v.webm", content_type="video/webm")
        self.assertTrue(v2); self.assertIsNone(e2)

    def test_consistency_empty(self):
        p = _make_file(self.tmp_path, "e.mp4", b"")
        v, e = SignatureScanner.verify_consistency(p, filename="e.mp4", content_type="video/mp4")
        self.assertFalse(v); self.assertIn("too small", e)
    def test_consistency_small(self):
        p = _make_file(self.tmp_path, "s.mp4", b"\x00\x00\x00\x10")
        v, e = SignatureScanner.verify_consistency(p, filename="s.mp4", content_type="video/mp4")
        self.assertFalse(v); self.assertIn("too small", e)
    def test_consistency_random(self):
        p = _make_file(self.tmp_path, "r.mp4", os.urandom(256))
        v, e = SignatureScanner.verify_consistency(p, filename="r.mp4", content_type="video/mp4")
        self.assertFalse(v); self.assertIn("failed signature scan", e)
    def test_consistency_nonexist(self):
        p = self.tmp_path / "n.mp4"
        v, e = SignatureScanner.verify_consistency(p, filename="n.mp4", content_type="video/mp4")
        self.assertFalse(v); self.assertIn("empty", e)
    def test_consistency_nulls(self):
        p = _make_file(self.tmp_path, "n.mp4", b"\x00" * 32)
        v, e = SignatureScanner.verify_consistency(p, filename="n.mp4", content_type="video/mp4")
        self.assertFalse(v); self.assertIn("failed signature scan", e)

    def test_detect_avi_requires_chunk(self):
        p = _make_file(self.tmp_path, "f.avi", b"RIFF\x00\x00\x00\x00WAVE" + b"\x00" * 20)
        self.assertIsNone(SignatureScanner.detect_format(p))
    def test_detect_ebml_both(self):
        self.assertEqual(SignatureScanner.detect_format(_make_file(self.tmp_path, "v.mkv", MKV_MAGIC)), "Matroska")
        self.assertEqual(SignatureScanner.detect_format(_make_file(self.tmp_path, "v.webm", WEBM_MAGIC)), "Matroska")


class TestIsolateUpload(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
    def tearDown(self):
        self.tmp_dir.cleanup()

    def _mock(self, name, ctype, data):
        class M:
            filename = name
            content_type = ctype
            @staticmethod
            def save(dst):
                with open(dst, "wb") as f:
                    f.write(data)
        return M()

    def test_mp4_ok(self):
        with isolate_upload(self._mock("v.mp4", "video/mp4", MP4_MAGIC)) as p:
            self.assertTrue(p.exists())
    def test_webm_ok(self):
        with isolate_upload(self._mock("v.webm", "video/webm", WEBM_MAGIC)) as p:
            self.assertTrue(p.exists())
    def test_mkv_ok(self):
        with isolate_upload(self._mock("v.mkv", "video/x-matroska", MKV_MAGIC)) as p:
            self.assertTrue(p.exists())
    def test_no_context_ok(self):
        with isolate_upload(self._mock(None, None, MP4_MAGIC)) as p:
            self.assertTrue(p.exists())
    def test_octet_stream_ok(self):
        with isolate_upload(self._mock("v.mp4", "application/octet-stream", MP4_MAGIC)) as p:
            self.assertTrue(p.exists())

    def test_png_spoof(self):
        with self.assertRaises(QuarantineError) as ctx:
            with isolate_upload(self._mock("m.mp4", "video/mp4", PNG_MAGIC)):
                pass
        self.assertIn("failed signature scan", str(ctx.exception))
    def test_text_spoof(self):
        with self.assertRaises(QuarantineError) as ctx:
            with isolate_upload(self._mock("e.mp4", "video/mp4", b"This is just a text file masquerading as video")):
                pass
        self.assertIn("failed signature scan", str(ctx.exception))
    def test_bad_ext(self):
        with self.assertRaises(QuarantineError) as ctx:
            with isolate_upload(self._mock("m.exe", "application/octet-stream", MP4_MAGIC)):
                pass
        self.assertIn("unsupported extension", str(ctx.exception))
    def test_bad_mime(self):
        with self.assertRaises(QuarantineError) as ctx:
            with isolate_upload(self._mock("v.mp4", "application/pdf", MP4_MAGIC)):
                pass
        self.assertIn("unsupported content type", str(ctx.exception))
    def test_empty(self):
        with self.assertRaises(QuarantineError) as ctx:
            with isolate_upload(self._mock("v.mp4", "video/mp4", b"")):
                pass
        self.assertIn("too small", str(ctx.exception))
    def test_mov_as_mp4(self):
        with self.assertRaises(QuarantineError) as ctx:
            with isolate_upload(self._mock("v.mp4", "video/mp4", MOV_MAGIC)):
                pass
        self.assertIn("possible content-type spoofing", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
