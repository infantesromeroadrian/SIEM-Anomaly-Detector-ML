#!/bin/bash
# =============================================================================
# SIEM Executive Overview - PDF Generator
# =============================================================================
# Convierte EXECUTIVE_OVERVIEW.html a PDF de alta calidad
#
# Requiere: Chrome/Chromium instalado
# Uso: ./generate_pdf.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HTML_FILE="${SCRIPT_DIR}/EXECUTIVE_OVERVIEW.html"
PDF_FILE="${SCRIPT_DIR}/SIEM_Executive_Overview.pdf"

echo "=============================================================================="
echo "  SIEM Executive Overview - PDF Generator"
echo "=============================================================================="
echo ""

# Verificar que el HTML existe
if [ ! -f "$HTML_FILE" ]; then
    echo "❌ ERROR: No se encuentra $HTML_FILE"
    exit 1
fi

echo "✅ HTML encontrado: $HTML_FILE"

# Detectar Chrome/Chromium
CHROME=""
if command -v google-chrome &> /dev/null; then
    CHROME="google-chrome"
elif command -v chromium-browser &> /dev/null; then
    CHROME="chromium-browser"
elif command -v chromium &> /dev/null; then
    CHROME="chromium"
elif [ -f "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
    CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
else
    echo "❌ ERROR: Chrome/Chromium no encontrado"
    echo ""
    echo "Instalar con:"
    echo "  Ubuntu/Debian: sudo apt install chromium-browser"
    echo "  Fedora/RHEL:   sudo dnf install chromium"
    echo "  macOS:         brew install --cask google-chrome"
    exit 1
fi

echo "✅ Chrome encontrado: $CHROME"
echo ""
echo "🔄 Generando PDF..."
echo "   Esto puede tardar 10-15 segundos..."
echo ""

# Generar PDF con Chrome headless
"$CHROME" \
    --headless \
    --disable-gpu \
    --no-sandbox \
    --print-to-pdf="$PDF_FILE" \
    --print-to-pdf-no-header \
    --no-pdf-header-footer \
    --run-all-compositor-stages-before-draw \
    --virtual-time-budget=10000 \
    "file://$HTML_FILE" \
    2>/dev/null

if [ $? -eq 0 ] && [ -f "$PDF_FILE" ]; then
    PDF_SIZE=$(du -h "$PDF_FILE" | cut -f1)
    echo "✅ PDF generado correctamente!"
    echo ""
    echo "=============================================================================="
    echo "  📄 Archivo:   $PDF_FILE"
    echo "  📊 Tamaño:    $PDF_SIZE"
    echo "=============================================================================="
    echo ""
    echo "💡 Abrir PDF:"
    echo "   Linux:   xdg-open \"$PDF_FILE\""
    echo "   macOS:   open \"$PDF_FILE\""
    echo "   Windows: start \"$PDF_FILE\""
    echo ""
else
    echo "❌ ERROR: Fallo al generar PDF"
    exit 1
fi
