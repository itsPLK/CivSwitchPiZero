"""Generate Pi LDN assets from the pinned CivSwitch submodule.
UDP loader and packaging follow esp32-ldn-civ7 by sean.
"""
from pathlib import Path
import base64, importlib.util, json, shutil, struct, subprocess

def build(root):
    civ = root / 'CivSwitch'
    out = root / 'build/ldn'
    out.mkdir(parents=True, exist_ok=True)
    stage = out / 'stage'
    pico = stage / 'PicoSwitch'
    pico.mkdir(parents=True, exist_ok=True)
    core = (civ / 'core.js').read_text()
    entry = '        remote_js_loader();'
    if core.count(entry) != 1:
        raise RuntimeError('Expected one remote loader entry point')
    (stage / 'core.js').write_text(core.replace(entry, (root / 'tools/ldn/udp_loader.js').read_text()))
    compressor = (civ / 'PicoSwitch/compress.js').read_text()
    if 'const MAX = 254;' not in compressor:
        raise RuntimeError('Unsupported compressor')
    (pico / 'compress.js').write_text(compressor.replace('const MAX = 254;', 'const MAX = 1000;'))
    modules = pico / 'node_modules'
    if not modules.exists():
        modules.symlink_to((root / 'build/stage/PicoSwitch/node_modules').resolve())
    subprocess.run(['node', 'compress.js'], cwd=pico, check=True)
    lines = [s for s in (pico / 'payload.txt').read_text().splitlines() if s.strip()]
    if not lines or max(map(len, lines)) > 1000:
        raise RuntimeError('Invalid chat payload')
    (out / 'chat_payload.h').write_text('#define CHAT_LINE_COUNT %d\nstatic const char *const CHAT_LINES[] = {\n%s\n};\n' % (len(lines), ',\n'.join(json.dumps(s).replace('?', r'\?') for s in lines)))
    instdir = civ / 'installer-creator'
    spec = importlib.util.spec_from_file_location('civinst', instdir / 'install.py')
    inst = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inst)
    wrapped = out / 'wrapped.js'
    wrapped.write_text('(async function() {\ntry{\n' + core + "\n} catch(e) { await log('EXCEPTION: '+e.message); await log(e.stack); }\n})();")
    # Resolve terser from our existing build dependency directory.
    shutil.copyfile(instdir / 'compress_stage.js', pico / 'compress_stage.js')
    subprocess.run(['node', str(pico / 'compress_stage.js'), str(wrapped), str(out / 'stage.hex')], check=True)
    template = (instdir / 'save_template.bin').read_bytes()
    if len(template) < 4096 or template[:4] != b'CIV7':
        raise RuntimeError('Invalid installer template')
    tpl = base64.b64encode(template)
    apply = inst.BLOCK.replace('__STAGER__', json.dumps(inst.STAGER)).replace('__STAGE_HEX__', json.dumps((out / 'stage.hex').read_text().strip())).replace('__TPL_B64_LEN__', str(len(tpl))).encode()
    for name, data in [('template.b64', tpl), ('apply.b64', base64.b64encode(apply))]:
        (out / name).write_bytes(data)
    print(f'[ldn] {len(lines)} chat lines; template={len(tpl)} apply={len(apply)} bytes')

if __name__ == '__main__':
    build(Path(__file__).resolve().parents[2])
