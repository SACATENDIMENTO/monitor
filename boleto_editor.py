"""
ZEUS — Boleto PDF Editor v2
Renderiza o PDF, usuário clica no campo, digita o novo valor.
Zero auto-detecção = zero erro de posicionamento.
"""
import re, io, os
from pypdf import PdfReader, PdfWriter

# ── Linha Digitável → Código de Barras ────────────────────────────────────
def linha_para_codigo44(linha):
    d = ''.join(c for c in linha if c.isdigit())
    if len(d) == 44: return d
    if len(d) != 47: return None
    banco_moeda = d[0:4]
    dig_geral   = d[32]
    fator_valor = d[33:47]
    livre1      = d[4:9]
    livre2      = d[10:20]
    livre3      = d[21:31]
    return banco_moeda + dig_geral + fator_valor + livre1 + livre2 + livre3

def formatar_linha(linha):
    d = ''.join(c for c in linha if c.isdigit())
    if len(d) < 47: return linha
    return f"{d[0:5]}.{d[5:10]} {d[10:15]}.{d[15:21]} {d[21:26]}.{d[26:32]} {d[32]} {d[33:47]}"

# ── Gerar barras I2of5 ────────────────────────────────────────────────────
def gerar_barras_i2of5(codigo44, width_pt, height_pt=40):
    I25 = {
        '0':(0,0,1,1,0),'1':(1,0,0,0,1),'2':(0,1,0,0,1),
        '3':(1,1,0,0,0),'4':(0,0,1,0,1),'5':(1,0,1,0,0),
        '6':(0,1,1,0,0),'7':(0,0,0,1,1),'8':(1,0,0,1,0),
        '9':(0,1,0,1,0),
    }
    N, W = 1.0, 2.5
    cod = codigo44
    if len(cod) % 2: cod = '0' + cod
    bars = [(True,N),(False,N),(True,N),(False,N)]
    for i in range(0, len(cod), 2):
        p1 = I25.get(cod[i],   (0,0,0,0,0))
        p2 = I25.get(cod[i+1], (0,0,0,0,0))
        for b, s in zip(p1, p2):
            bars.append((True,  W if b else N))
            bars.append((False, W if s else N))
    bars += [(True,W),(False,N),(True,N)]
    total = sum(w for _,w in bars)
    scale = width_pt / total
    rects = []; x = 0.0
    for is_black, units in bars:
        w = units * scale
        if is_black: rects.append((x, w))
        x += w
    return rects

# ── Criar overlay com substituições ───────────────────────────────────────
def criar_overlay(pw, ph, substituicoes, codigo44=None, barcode_rect=None):
    """
    substituicoes = [(x, y, w, h, novo_texto, fonte, tamanho), ...]
    barcode_rect  = (x, y, w, h) posição do código de barras
    """
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(pw, ph))

    for (x, y, w, h, texto, fonte, tam) in substituicoes:
        # Cobrir original com branco
        c.setFillColor(colors.white)
        c.setStrokeColor(colors.white)
        c.rect(x, y, w, h, fill=1, stroke=0)
        # Escrever novo texto
        if texto:
            c.setFillColor(colors.black)
            try: c.setFont(fonte, tam)
            except: c.setFont("Helvetica", tam)
            c.drawString(x + 1, y + 2, texto)

    # Código de barras
    if codigo44 and barcode_rect:
        bx, by, bw, bh = barcode_rect
        c.setFillColor(colors.white)
        c.rect(bx, by, bw, bh + 4, fill=1, stroke=0)
        c.setFillColor(colors.black)
        for rx, rw in gerar_barras_i2of5(codigo44, bw, bh):
            c.rect(bx + rx, by, max(0.5, rw), bh, fill=1, stroke=0)

    c.save()
    return buf.getvalue()

def aplicar_overlay(pdf_bytes, overlay_bytes):
    reader  = PdfReader(io.BytesIO(pdf_bytes))
    overlay = PdfReader(io.BytesIO(overlay_bytes))
    writer  = PdfWriter()
    for i, page in enumerate(reader.pages):
        if i < len(overlay.pages):
            page.merge_page(overlay.pages[i])
        writer.add_page(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()

def get_pdf_page_size(pdf_bytes):
    try:
        r = PdfReader(io.BytesIO(pdf_bytes))
        p = r.pages[0]
        return float(p.mediabox.width), float(p.mediabox.height)
    except:
        return 595.0, 842.0
