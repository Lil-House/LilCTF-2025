import os
from PIL import Image, ImageDraw, ImageFont


flag = os.environ.get(
    "INSERT_FLAG",
    "LILCTF{i_dont_want_to_implement_it_by_myself_ai_generated_that_code}",
)
lines = "\n".join(flag[i : i + 24] for i in range(0, len(flag), 24))

template = Image.open("assets/template.png")
draw = ImageDraw.Draw(template)
font = ImageFont.truetype("assets/JetBrainsMono-Regular.ttf", 60)
draw.text((116, 660), lines, fill="white", font=font, spacing=24, align="center")

template.save("avatar.png")
