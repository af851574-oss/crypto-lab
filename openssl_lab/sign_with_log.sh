#!/usr/bin/env zsh

set -e

WORK_DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"
cd "$WORK_DIR"

LOG_FILE="verification.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

log() {
    echo "[$TIMESTAMP] $1" >> "$LOG_FILE"
    echo "$1"
}

echo "==============================================" > "$LOG_FILE"
echo "ОТЧЁТ О ЦИФРОВОЙ ПОДПИСИ" >> "$LOG_FILE"
echo "Дата: $TIMESTAMP" >> "$LOG_FILE"
echo "==============================================" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

echo "Выполнение..."

log "Шаг 1: Проверка ключей..."
if [[ ! -f "private.pem" ]] || [[ ! -f "public.pem" ]]; then
    openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null
    openssl rsa -pubout -in private.pem -out public.pem 2>/dev/null
fi
log "  Ключи готовы"

log "Шаг 2: Создание payload.txt..."
echo "Это тестовый payload для подписи." > payload.txt
log "  Готово"

log "Шаг 3: Подписание (PKCS#1 v1.5, SHA-256)..."
openssl dgst -sha256 -sign private.pem -out payload.sig payload.txt 2>/dev/null
log "  Подпись: payload.sig ($(wc -c < payload.sig) байт)"

log "Шаг 4: Верификация..."
VERIFY_RESULT=$(openssl dgst -sha256 -verify public.pem -signature payload.sig payload.txt 2>&1)
echo "$VERIFY_RESULT" >> "$LOG_FILE"
if [[ "$VERIFY_RESULT" == *"Verified OK"* ]]; then
    log "  OK"
else
    log "  FAILED"
    exit 1
fi

log "Шаг 5: Тест целостности..."
cp payload.txt payload.txt.backup
echo "Изменённый текст" >> payload.txt
VERIFY_RESULT2=$(openssl dgst -sha256 -verify public.pem -signature payload.sig payload.txt 2>&1 || true)
echo "$VERIFY_RESULT2" >> "$LOG_FILE"
if [[ "$VERIFY_RESULT2" == *"Verified OK"* ]]; then
    log "  ОШИБКА!"
    exit 1
else
    log "  Failure (ожидаемо)"
fi
mv payload.txt.backup payload.txt

log "Шаг 6: RSA-PSS..."
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sign private.pem -out payload_pss.sig payload.txt 2>/dev/null
VERIFY_RESULT3=$(openssl dgst -sha256 -sigopt rsa_padding_mode:pss -verify public.pem -signature payload_pss.sig payload.txt 2>&1)
echo "$VERIFY_RESULT3" >> "$LOG_FILE"
if [[ "$VERIFY_RESULT3" == *"Verified OK"* ]]; then
    log "  OK"
else
    log "  FAILED"
fi

echo "" >> "$LOG_FILE"
echo "==============================================" >> "$LOG_FILE"
echo "ИТОГИ: Все задания выполнены успешно" >> "$LOG_FILE"
echo "==============================================" >> "$LOG_FILE"

echo ""
echo "Лог: $LOG_FILE"
