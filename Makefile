.PHONY: all build

all: build

build:
    @echo "Building the project..."
    python3 install.py
	@echo "Build complete."
