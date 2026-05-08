#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os

paths = [
    r"H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat",
]

print("Checking VsDevCmd.bat paths:")
for p in paths:
    exists = os.path.exists(p)
    print(f"  {'[OK]' if exists else '[NOT FOUND]'} {p}")