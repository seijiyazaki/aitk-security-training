import sys
from PIL import Image, ImageDraw, ImageFilter
S = 1024; out = sys.argv[1]
def lerp(a, b, t): return tuple(int(a[i] + (b[i]-a[i])*t) for i in range(3))
bg = Image.new("RGBA", (S, S)); px = bg.load()
c1, c2 = (6, 26, 40), (20, 98, 178)
for y in range(S):
    for x in range(S):
        t = min(1, max(0, (x*0.3 + y*0.7) / S)); px[x, y] = lerp(c1, c2, t) + (255,)
mask = Image.new("L", (S, S), 0); ImageDraw.Draw(mask).rounded_rectangle([0, 0, S-1, S-1], radius=230, fill=255)
icon = Image.new("RGBA", (S, S), (0, 0, 0, 0)); icon.paste(bg, (0, 0), mask)
cx = S/2
def qbez(p0, p1, p2, n=40):
    return [((1-t)**2*p0[0]+2*(1-t)*t*p1[0]+t*t*p2[0], (1-t)**2*p0[1]+2*(1-t)*t*p1[1]+t*t*p2[1]) for t in [i/n for i in range(n+1)]]
def shield(ins=0):
    w, top, shoulder, side, bot = 330-ins, 150+ins*1.1, 235+ins, 540, 900-ins*1.3
    pts = [(cx, top)]
    pts += qbez((cx, top), (cx+w*0.55, top+40), (cx+w, shoulder), 20)[1:]
    pts += [(cx+w, side)]
    pts += qbez((cx+w, side), (cx+w, bot-110), (cx, bot))[1:]
    pts += qbez((cx, bot), (cx-w, bot-110), (cx-w, side))[1:]
    pts += [(cx-w, shoulder)]
    pts += qbez((cx-w, shoulder), (cx-w*0.55, top+40), (cx, top), 20)[1:]
    return pts
glow = Image.new("RGBA", (S, S), (0, 0, 0, 0)); ImageDraw.Draw(glow).polygon(shield(0), fill=(70, 200, 255, 140))
icon = Image.alpha_composite(icon, glow.filter(ImageFilter.GaussianBlur(45)))
d = ImageDraw.Draw(icon)
d.polygon(shield(0), fill=(236, 246, 255, 255))
d.polygon(shield(38), fill=(9, 36, 56, 255))
cyan, green, orange = (70, 216, 255), (104, 232, 164), (255, 138, 48)
L = [[(cx-175, 360), (cx-175, 500), (cx-175, 640)],
     [(cx, 330), (cx, 470), (cx, 610)],
     [(cx+175, 400), (cx+175, 560)]]
for a, b in zip(L, L[1:]):
    for p in a:
        for q in b:
            d.line([p, q], fill=(70, 216, 255, 170), width=11)
r = 38
for li, layer in enumerate(L):
    for p in layer:
        d.ellipse([p[0]-r-9, p[1]-r-9, p[0]+r+9, p[1]+r+9], fill=(9, 36, 56, 255))
        d.ellipse([p[0]-r, p[1]-r, p[0]+r, p[1]+r], fill=(green if li == 2 else cyan) + (255,))
# anomaly point near the shield tip, with a glow ring
o = (cx, 760)
g2 = Image.new("RGBA", (S, S), (0, 0, 0, 0)); ImageDraw.Draw(g2).ellipse([o[0]-70, o[1]-70, o[0]+70, o[1]+70], fill=orange + (170,))
icon = Image.alpha_composite(icon, g2.filter(ImageFilter.GaussianBlur(22)))
d = ImageDraw.Draw(icon)
d.ellipse([o[0]-40, o[1]-40, o[0]+40, o[1]+40], fill=orange + (255,))
d.line([L[1][2], (o[0], o[1]-40)], fill=(255, 138, 48, 200), width=9)
icon.save(out + "_1024.png")
for n in (36, 72, 144):
    icon.resize((n, n), Image.LANCZOS).save(f"{out}_{n}.png")
# preview sheet: small sizes on the nav-like light background
sheet = Image.new("RGBA", (420, 160), (245, 247, 250, 255))
x = 20
for n in (36, 72, 144):
    im = Image.open(f"{out}_{n}.png"); sheet.alpha_composite(im, (x, 8)); x += n + 30
sheet.save(out + "_sheet.png")
