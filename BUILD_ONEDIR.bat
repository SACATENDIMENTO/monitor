@echo off
title ZEUS — Build EXE (pasta)
echo.
echo Compilando ZEUS em modo pasta (abre instantaneo)...
echo.

python -m PyInstaller ^
    --onedir ^
    --noconsole ^
    --name "ZEUS_EmailMonitor" ^
    --icon zeus_icon.ico ^
    --add-data "zeus_engine.py;." ^
    --add-data "zeus_worker.py;." ^
    --add-data "zeus_security.py;." ^
    --add-data "boleto_editor.py;." ^
    --hidden-import PyQt5 ^
    --hidden-import PyQt5.QtWidgets ^
    --hidden-import PyQt5.QtCore ^
    --hidden-import PyQt5.QtGui ^
    --hidden-import sqlite3 ^
    --hidden-import sklearn ^
    --hidden-import sklearn.naive_bayes ^
    --hidden-import sklearn.feature_extraction.text ^
    --hidden-import reportlab ^
    --hidden-import reportlab.pdfgen ^
    --hidden-import reportlab.lib.colors ^
    --hidden-import pypdf ^
    --hidden-import pdfplumber ^
    --hidden-import PIL ^
    --hidden-import cryptography ^
    --hidden-import cryptography.fernet ^
    --hidden-import email ^
    --hidden-import imaplib ^
    --hidden-import smtplib ^
    --hidden-import asyncio ^
    --hidden-import multiprocessing ^
    --hidden-import zeus_engine ^
    --hidden-import zeus_worker ^
    --hidden-import zeus_security ^
    --hidden-import boleto_editor ^
    --clean ^
    --noconfirm ^
    zeus_mail.py

if exist "dist\ZEUS_EmailMonitor\ZEUS_EmailMonitor.exe" (
    echo.
    echo ================================================
    echo  BUILD CONCLUIDO!
    echo  Pasta: dist\ZEUS_EmailMonitor\
    echo  Rode:  dist\ZEUS_EmailMonitor\ZEUS_EmailMonitor.exe
    echo ================================================
) else (
    echo [ERRO] Falhou. Veja erros acima.
)

rmdir /s /q build 2>nul
del ZEUS_EmailMonitor.spec 2>nul
pause
