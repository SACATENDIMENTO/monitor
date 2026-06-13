@echo off
title ZEUS — Build Debug EXE
echo.
echo Compilando versao DEBUG (com console)...
echo.

python -m PyInstaller ^
    --onefile ^
    --console ^
    --name "ZEUS_Debug" ^
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

if exist dist\ZEUS_Debug.exe (
    copy dist\ZEUS_Debug.exe ZEUS_Debug.exe >nul
    echo.
    echo Pronto! Rode ZEUS_Debug.exe para ver o erro.
) else (
    echo ERRO na compilacao.
)

rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del ZEUS_Debug.spec 2>nul
pause