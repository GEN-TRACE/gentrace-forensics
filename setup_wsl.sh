#!/usr/bin/env bash
# WSL-Ubuntu 개발 환경 셋업. 저장소 루트에서 최초 1회 실행.
#
#   sed -i 's/\r$//' setup_wsl.sh   # Windows에서 클론했다면 줄바꿈 정리 (한 번)
#   bash ./setup_wsl.sh
#
# 환경변수로 조정:
#   VENV=~/venvs/gentrace   가상환경 경로
#   EXTRAS=dev,acquisition  설치할 optional 의존성 그룹

set -euo pipefail

VENV="${VENV:-$HOME/venvs/gentrace}"
EXTRAS="${EXTRAS:-dev,acquisition}"

if [ ! -f pyproject.toml ]; then
    echo "error: 저장소 루트에서 실행하세요 (pyproject.toml 이 안 보임)" >&2
    exit 1
fi

echo "[1/3] 시스템 패키지 설치 (sudo)"
sudo apt-get update
sudo apt-get install -y \
    python3-venv python3-dev build-essential pkg-config \
    libtsk-dev libewf-dev libbde-dev libfsntfs-dev

echo "[2/3] 가상환경: $VENV"
python3 -m venv --prompt gentrace "$VENV"
# shellcheck source=/dev/null
source "$VENV/bin/activate"

echo "[3/3] 파이썬 의존성: .[$EXTRAS]"
pip install --upgrade pip setuptools wheel
pip install -e ".[$EXTRAS]"

echo
echo "완료. 이후 새 셸에서:"
echo "  source $VENV/bin/activate"
echo "  gentrace --help"
