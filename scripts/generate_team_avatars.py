"""
Generates professional 600x600 team avatar photos for TraceMail AI contributors.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

TEAM_MEMBERS = [
    {
        "filename": "leader.jpg",
        "role": "TEAM LEAD",
        "sub": "Frontend & Project Mgmt",
        "accent": (37, 99, 235),  # Blue
        "symbol": "TL"
    },
    {
        "filename": "backend.jpg",
        "role": "BACKEND TEAM",
        "sub": "FastAPI & Database",
        "accent": (124, 58, 237),  # Purple
        "symbol": "BE"
    },
    {
        "filename": "ai.jpg",
        "role": "AI ENGINE TEAM",
        "sub": "ML & Phishing Models",
        "accent": (5, 150, 105),  # Green
        "symbol": "AI"
    },
    {
        "filename": "threat.jpg",
        "role": "THREAT INTEL TEAM",
        "sub": "VirusTotal & OSINT",
        "accent": (220, 38, 38),  # Red
        "symbol": "TI"
    },
    {
        "filename": "maps.jpg",
        "role": "MAPS ENGINE TEAM",
        "sub": "Attack Path & GeoJSON",
        "accent": (234, 88, 12),  # Orange
        "symbol": "MP"
    },
    {
        "filename": "reports.jpg",
        "role": "REPORTS TEAM",
        "sub": "Forensics & QA Lead",
        "accent": (8, 145, 178),  # Cyan
        "symbol": "RP"
    },
]

out_dir = Path("assets/team")
out_dir.mkdir(parents=True, exist_ok=True)

size = (600, 600)

for member in TEAM_MEMBERS:
    img = Image.new("RGB", size, (15, 23, 42))  # Dark slate background #0f172a
    draw = ImageDraw.Draw(img)
    
    # Outer accent border
    draw.rectangle([(10, 10), (590, 590)], outline=member["accent"], width=3)
    
    # Inner glowing avatar circle
    cx, cy, r = 300, 220, 130
    draw.ellipse([(cx - r - 8, cy - r - 8), (cx + r + 8, cy + r + 8)], outline=member["accent"], width=4)
    draw.ellipse([(cx - r, cy - r), (cx + r, cy + r)], fill=(30, 41, 59))
    
    # Draw Symbol in circle
    try:
        font_large = ImageFont.truetype("arial.ttf", 90)
        font_title = ImageFont.truetype("arial.ttf", 32)
        font_sub = ImageFont.truetype("arial.ttf", 22)
        font_badge = ImageFont.truetype("arial.ttf", 16)
    except Exception:
        font_large = ImageFont.load_default()
        font_title = font_large
        font_sub = font_large
        font_badge = font_large

    # Center symbol
    draw.text((cx, cy), member["symbol"], fill=member["accent"], font=font_large, anchor="mm")
    
    # Title and subtitle
    draw.text((300, 420), member["role"], fill=(248, 250, 252), font=font_title, anchor="mm")
    draw.text((300, 470), member["sub"], fill=(148, 163, 184), font=font_sub, anchor="mm")
    
    # SIH 2026 Badge
    draw.rectangle([(200, 520), (400, 555)], fill=(30, 41, 59), outline=member["accent"], width=1)
    draw.text((300, 537), "SIH 2026 CONTRIBUTOR", fill=(203, 213, 225), font=font_badge, anchor="mm")
    
    out_path = out_dir / member["filename"]
    img.save(out_path, "JPEG", quality=95)
    print(f"Generated: {out_path}")
