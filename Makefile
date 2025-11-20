dev-up:
  docker compose up -d
dev-down:
  docker compose down -v
build:
  cd cmd/core-service && go build -o dist/core-service .
setup-python:
  python3 -m venv scripts/.venv
  scripts/.venv/bin/pip install --quiet restrictedpython
