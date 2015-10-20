QT += core
QT -= gui

TARGET = qt-crypt
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

unix:LIBS += -lssl -lcrypto

SOURCES += main.cpp

