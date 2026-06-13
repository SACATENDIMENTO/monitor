@echo off
title ZEUS — Build EXE
color 0A
echo.
echo  ZEUS Email Monitor — Build EXE
echo.

:: Verificar Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERRO] Python nao encontrado. Instale Python 3.10+ de python.org
    pause & exit /b 1
)
echo [OK] Python encontrado

:: Instalar dependencias usando python -m pip
echo.
echo [1/4] Instalando dependencias...
python -m pip install pyinstaller --quiet
python -m pip install pyarmor --quiet
python -m pip install cryptography PyQt5 pypdf reportlab pillow pdfplumber scikit-learn --quiet
echo [OK] Dependencias instaladas

:: Criar pasta temporaria
echo.
echo [2/4] Preparando arquivos...
if exist build_temp rmdir /s /q build_temp
mkdir build_temp

:: Tentar ofuscar com PyArmor
python -m pyarmor gen --output build_temp zeus_mail.py zeus_engine.py zeus_worker.py zeus_security.py boleto_editor.py 2>nul
if errorlevel 1 (
    echo [INFO] Copiando arquivos sem ofuscacao...
    if exist zeus_mail.py     copy zeus_mail.py     build_temp\ >nul
    if exist zeus_engine.py   copy zeus_engine.py   build_temp\ >nul
    if exist zeus_worker.py   copy zeus_worker.py   build_temp\ >nul
    if exist zeus_security.py copy zeus_security.py build_temp\ >nul
    if exist boleto_editor.py copy boleto_editor.py build_temp\ >nul
) else (
    echo [OK] Codigo ofuscado
)

:: Criar icone
if exist CRIAR_ICONE.py (
    echo [OK] Criando icone...
    python CRIAR_ICONE.py
)

:: Definir flag do icone
set ICON_FLAG=
if exist zeus_icon.ico set ICON_FLAG=--icon=zeus_icon.ico

:: Build com PyInstaller
echo.
echo [3/4] Compilando EXE - aguarde 3-5 minutos...
python -m PyInstaller ^
    --onefile ^
    --noconsole ^
    --name "ZEUS_EmailMonitor" ^
    %ICON_FLAG% ^
    --add-data "build_temp\zeus_engine.py;." ^
    --add-data "build_temp\zeus_worker.py;." ^
    --add-data "build_temp\zeus_security.py;." ^
    --add-data "build_temp\boleto_editor.py;." ^
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
    build_temp\zeus_mail.py

:: Verificar resultado
echo.
echo [4/4] Finalizando...
if exist dist\ZEUS_EmailMonitor.exe (
    copy dist\ZEUS_EmailMonitor.exe ZEUS_EmailMonitor.exe >nul
    echo.
    echo ================================================
    echo  BUILD CONCLUIDO COM SUCESSO!
    echo  Arquivo: ZEUS_EmailMonitor.exe
    echo ================================================
) else (
    echo [ERRO] EXE nao gerado. Veja os erros acima.
)

:: Limpar temporarios
rmdir /s /q build_temp 2>nul
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del *.spec 2>nul

echo.
pause