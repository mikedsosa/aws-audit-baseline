PYTHONPATH := src
export PYTHONPATH

.PHONY: test lint fmt validate offline-plan

test:
	python -m pytest

lint:
	ruff check src tests
	ruff format --check src tests

fmt:
	ruff format src tests
	terraform -chdir=terraform fmt -recursive

validate:
	terraform -chdir=terraform init -backend=false -input=false
	terraform -chdir=terraform validate

offline-plan:
	./scripts/offline-plan.sh
