"""
Cria o ícone do ZEUS (zeus_icon.ico) — raio vermelho no fundo preto.
Roda antes do BUILD_ZEUS.bat
"""
import struct, zlib, os

def create_zeus_ico():
    """Gera um ícone ICO 32x32 com raio dourado no fundo preto."""
    try:
        from PIL import Image, ImageDraw, ImageFont
        size = 256
        img = Image.new('RGBA', (size, size), (0, 0, 0, 255))
        draw = ImageDraw.Draw(img)
        
        # Círculo vermelho de fundo
        draw.ellipse([10, 10, size-10, size-10], fill=(229, 9, 20, 255))
        
        # Raio (⚡) em amarelo
        cx, cy = size//2, size//2
        bolt = [
            (cx+20, 20),
            (cx-5,  cy-10),
            (cx+15, cy-10),
            (cx-20, size-20),
            (cx+5,  cy+10),
            (cx-15, cy+10),
        ]
        draw.polygon(bolt, fill=(255, 220, 0, 255))
        
        # Salvar como ICO com múltiplos tamanhos
        sizes = [(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)]
        imgs = [img.resize(s, Image.LANCZOS) for s in sizes]
        imgs[0].save('zeus_icon.ico', format='ICO',
                     sizes=[(s[0],s[1]) for s in sizes],
                     append_images=imgs[1:])
        print("zeus_icon.ico criado com sucesso!")
        return True
    except ImportError:
        print("Pillow nao instalado — icone padrao sera usado")
        return False
    except Exception as e:
        print(f"Erro ao criar icone: {e}")
        return False

if __name__ == '__main__':
    create_zeus_ico()
