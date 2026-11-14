"""Release packaging must reject the USB-only image that caused the CI regression."""
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))
from build_image import CpioNewcBuilder
from verify_ldn_image import verify


class LdnImageTest(unittest.TestCase):
    def test_required_components(self):
        files = {
            'nexmon': b'driver=6.12.2 firmware=0.2\n',
            'ldn/template.b64': b'template',
            'ldn/apply.b64': b'apply',
            'modules/armv6l/brcmfmac.ko': b'armv6 driver',
            'modules/armv7l/brcmfmac.ko': b'armv7 driver',
            'lib/firmware/brcm/brcmfmac43430-sdio.raspberrypi,model-zero-w.bin': b'firmware',
            'lib/firmware/brcm/brcmfmac43430b0-sdio.raspberrypi,model-zero-2-w.bin': b'firmware',
        }
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'initramf.gz'
            def pack(entries):
                cpio = CpioNewcBuilder()
                for name, content in entries.items():
                    cpio.add_file(name, content)
                path.write_bytes(cpio.finish_gzip())
            pack(files)
            with contextlib.redirect_stdout(io.StringIO()):
                verify(path)
            for missing in files:
                with self.subTest(missing=missing):
                    pack({k: v for k, v in files.items() if k != missing})
                    with self.assertRaises(ValueError):
                        verify(path)
            pack(dict(files, **{'modules/armv7l/brcmfmac-cyw.ko': b'stock driver'}))
            with self.assertRaisesRegex(ValueError, 'Stock driver'):
                verify(path)


if __name__ == '__main__':
    unittest.main()
