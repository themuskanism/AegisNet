"""Package tracked source, trusted artifacts and built UI; exclude local secrets/data."""
from pathlib import Path
import hashlib
import subprocess
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    files = {Path(name) for name in tracked if name}
    files.update(path.relative_to(root) for path in (root / 'frontend/dist').rglob('*') if path.is_file())
    required = {'frontend/dist/index.html', 'artifacts/model.joblib', 'artifacts/metadata.json', 'artifacts/cnn_bilstm.pt'}
    assert required <= {path.as_posix() for path in files}, 'Build frontend and restore model artifacts first'
    for path in files:
        assert path.name not in {'.env', 'analyst-token.txt'}
        assert not ({'.git', '.venv', 'node_modules', '__pycache__', 'benchmark'} & set(path.parts))
    destination = root.parent / 'AegisNet-2.0.zip'
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(root / path, 'AegisNet/' + path.as_posix())
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix('.zip.sha256').write_text(digest + '  ' + destination.name + '\n')
    print(f'{destination.name}: {len(files)} files, {destination.stat().st_size} bytes, SHA256 {digest}')


if __name__ == '__main__':
    main()
