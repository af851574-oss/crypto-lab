#!/usr/bin/env zsh

set -e  

WORK_DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"
cd "$WORK_DIR"


if [[ ! -f "private.pem" ]] || [[ ! -f "public.pem" ]]; then
    echo "Генерация пары ключей RSA 2048..."
    openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null
    openssl rsa -pubout -in private.pem -out public.pem 2>/dev/null
    echo "  Ключи сгенерированы: private.pem, public.pem"
else
    echo "Ключи уже существуют, пропускаем генерацию."
fi


time openssl dgst -sha256 -sign private.pem -out payload.sig payload.txt 2>&1
echo " Файл подписан: payload.sig"
echo "  Размер подписи: $(wc -c < payload.sig) байт"
echo ""


if openssl dgst -sha256 -verify public.pem -signature payload.sig payload.txt 2>&1; then
    echo "  Верификация успешна: Verified OK"
else
    echo "  ✗ Верификация не пройдена!"
    exit 1
fi
echo ""


cp payload.txt payload.txt.backup
echo "Изменённый текст" >> payload.txt
echo "  Файл изменён, повторная верификация..."

if openssl dgst -sha256 -verify public.pem -signature payload.sig payload.txt 2>&1; then
    echo " ОШИБКА: Верификация прошла с изменённым файлом!"
    exit 1
else
    echo " Верификация не пройдена (ожидаемо): Verification failure"
fi

# Восстановление исходного файла
mv payload.txt.backup payload.txt
echo "  ✓ Файл payload.txt восстановлен"
echo ""


openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sign private.pem -out payload_pss.sig payload.txt 2>/dev/null
echo "RSA-PSS подпись создана: payload_pss.sig"

echo "Верификация RSA-PSS..."
if openssl dgst -sha256 -sigopt rsa_padding_mode:pss -verify public.pem -signature payload_pss.sig payload.txt 2>&1; then
    echo "RSA-PSS верификация успешна"
else
    echo "RSA-PSS верификация не пройдена!"
fi
echo ""
