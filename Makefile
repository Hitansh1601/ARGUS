.PHONY: install data features train alert test test-fast test-e2e baseline clean
# Windows 10+ primary: use .\tasks.ps1 <task>. Makefile kept for compat.
# Use `python` (not `python3`) for Windows.

install:
	python -m pip install -r requirements.txt

data:
	python simulator/generator.py

features:
	python src/feature_engineering.py

train:
	python src/train_model.py

train-fast:
	python src/train_model.py --no-plots

alert:
	python -m src.argus_alert --scenario ransomware_like

baseline:
	python argus_baseline.py

test:
	python -m pytest -v

test-fast:
	python -m pytest -m "not e2e" -v

test-e2e:
	python -m pytest -m e2e -v

clean:
	python -c "import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]; list(map(lambda p: p.unlink(missing_ok=True), pathlib.Path('.').rglob('*.pyc')))"
