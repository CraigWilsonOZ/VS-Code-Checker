#!/usr/bin/env bash
set -e

VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

echo "Installing dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install -r requirements.txt --quiet

echo ""
echo "Setup complete."
echo "Activate the virtual environment with:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "Then run:"
echo "  python main.py --help"
