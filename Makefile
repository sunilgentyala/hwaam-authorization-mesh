.PHONY: install test benchmark results demo

install:
	python -m pip install -e .

test:
	python scripts/run_tests.py

benchmark:
	python scripts/benchmark.py --iterations 20000

results:
	python scripts/generate_results.py

demo:
	python examples/demo.py
