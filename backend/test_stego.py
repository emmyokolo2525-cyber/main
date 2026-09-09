from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from envelope import canonical_metadata_hash
from stego import embed_metadata, extract_metadata, sha256_file


class SteganographyTest(unittest.TestCase):
    def test_embeds_and_extracts_metadata_from_encoded_video(self) -> None:
        if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
            self.skipTest("ffmpeg and ffprobe are required")

        with tempfile.TemporaryDirectory(prefix="harpocrates-stego-test-") as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "source.mp4"
            embedded = tmp_path / "embedded.mp4"
            subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-v",
                    "error",
                    "-f",
                    "lavfi",
                    "-i",
                    "testsrc=size=320x240:rate=30",
                    "-t",
                    "3",
                    "-pix_fmt",
                    "yuv420p",
                    str(source),
                ],
                check=True,
            )

            metadata = {
                "protocol": "harpocrates",
                "version": 1,
                "tier": "silent",
                "sourceHash": sha256_file(source),
                "proofId": "11" * 32,
                "timestamp": "2026-06-18T00:00:00.000Z",
                "fileName": "source.mp4",
            }

            embed_metadata(source, embedded, metadata)

            self.assertNotEqual(sha256_file(source), sha256_file(embedded))
            self.assertEqual(len(canonical_metadata_hash(metadata)), 64)
            self.assertEqual(extract_metadata(embedded), metadata)


if __name__ == "__main__":
    unittest.main()
