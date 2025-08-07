ACTIVATE_VENV=./venv/bin/activate

.PHONY: docs docs-apidoc docs-html docs-clean docs-serve

docs-apidoc:
	. ./venv/bin/activate && sphinx-apidoc src/bits -o docs/source

docs-build: docs-apidoc
	. ./venv/bin/activate && sphinx-build -b html docs/source docs/build

docs-clean:
	rm -rf docs/build/

docs: docs-clean docs-build

docs-serve:
	./venv/bin/python -m http.server -d docs/build/ -b 127.0.0.1 8000
