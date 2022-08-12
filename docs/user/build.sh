#!/bin/bash

pandoc --standalone --to man adb.1.md -o adb.1
pandoc --standalone --to html adb.1.md -o adb.1.html
