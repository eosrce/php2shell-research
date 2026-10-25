PY ?= python3

.PHONY: test smoke compile clean

test:
	$(PY) -m unittest discover -s tests -v
	$(PY) src/tools/fpm_chain_smoke.py
	$(PY) src/tools/fpm_reclaim_smoke.py

smoke:
	$(PY) src/tools/fpm_chain_smoke.py
	$(PY) src/tools/fpm_reclaim_smoke.py

compile:
	$(PY) -m py_compile $$(find src tests -name '*.py')

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
