#!/bin/bash
# Script to regenerate the Open Graph share preview image for WhatsApp / Social Media
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

if [ ! -f "$CHROME" ]; then
  echo "Google Chrome not found at $CHROME"
  exit 1
fi

TMP_HTML="/tmp/abnl-og-template.html"
TMP_PNG="/tmp/abnl-og-temp.png"
OUTPUT_JPG="$DIR/og-image.jpg"

cat << 'EOF' > "$TMP_HTML"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@700;800;900&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    width: 1200px;
    height: 630px;
    background: radial-gradient(ellipse at 50% 50%, #2f060c 0%, #170205 60%, #0a0103 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Plus Jakarta Sans', sans-serif;
    position: relative;
    overflow: hidden;
  }
  .frame-border {
    position: absolute;
    inset: 18px;
    border: 1.5px solid rgba(212, 175, 55, 0.45);
    border-radius: 20px;
    pointer-events: none;
  }
  .frame-inner {
    position: absolute;
    inset: 26px;
    border: 1px solid rgba(212, 175, 55, 0.2);
    border-radius: 14px;
    pointer-events: none;
  }
  .center-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    width: 580px;
    z-index: 10;
  }
  .logo-card {
    background: #ffffff;
    width: 530px;
    padding: 30px 38px 24px;
    border-radius: 26px;
    border: 3.5px solid #d4af37;
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.75), 0 0 60px rgba(212, 175, 55, 0.3);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    margin-bottom: 22px;
  }
  .logo-card img {
    width: 100%;
    max-height: 220px;
    object-fit: contain;
    display: block;
  }
  .menu-badge {
    background: linear-gradient(135deg, #d4af37 0%, #f7e7a9 50%, #d4af37 100%);
    color: #1a0306;
    font-family: 'Cinzel', serif;
    font-size: 23px;
    font-weight: 800;
    letter-spacing: 4px;
    text-transform: uppercase;
    padding: 10px 36px;
    border-radius: 40px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
    margin-bottom: 12px;
  }
  .tagline {
    color: #f7e7a9;
    font-size: 20px;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-shadow: 0 2px 10px rgba(0,0,0,0.9);
  }
</style>
</head>
<body>
  <div class="frame-border"></div>
  <div class="frame-inner"></div>
  <div class="center-container">
    <div class="logo-card">
      <img src="file://LOGO_PATH_PLACEHOLDER" alt="Absolute Bar & Lounge">
    </div>
    <div class="menu-badge">Food &amp; Bar Menu</div>
    <div class="tagline">Explore Our Complete Menu Online</div>
  </div>
</body>
</html>
EOF

sed -i '' "s|LOGO_PATH_PLACEHOLDER|$DIR/logo.png|g" "$TMP_HTML"

"$CHROME" --headless --disable-gpu --screenshot="$TMP_PNG" --window-size=1200,630 --hide-scrollbars "$TMP_HTML"
sips -s format jpeg -s formatOptions 92 "$TMP_PNG" --out "$OUTPUT_JPG"
rm -f "$TMP_HTML" "$TMP_PNG"
echo "Successfully generated $OUTPUT_JPG ($(du -h "$OUTPUT_JPG" | cut -f1))"
