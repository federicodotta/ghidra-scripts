# ghidra-scripts
[![](https://img.shields.io/github/stars/federicodotta/ghidra-scripts.svg?color=yellow)](https://github.com/federicodotta/ghidra-scripts)
[![](https://img.shields.io/github/forks/federicodotta/ghidra-scripts.svg?color=green)](https://github.com/federicodotta/ghidra-scripts)
[![](https://img.shields.io/github/watchers/federicodotta/ghidra-scripts.svg?color=red)](https://github.com/federicodotta/ghidra-scripts)
[![](https://img.shields.io/badge/license-MIT%20License-red.svg?color=lightgray)](https://opensource.org/licenses/MIT) 
[![](https://img.shields.io/badge/twitter-apps3c-blue.svg)](https://twitter.com/apps3c)

A collection of my Ghidra scripts.

## iOS	
* **[FOX](https://github.com/federicodotta/ghidra-scripts/tree/master/FOX/)**. This script locates all calls to *objc_msgSend* family functions, tries to infer the actual method that gets referenced, and adds cross-references, potential cross-references and useful comments.

## Misc
* **[ExportToGzf](https://github.com/federicodotta/ghidra-scripts/tree/master/ExportToGzf/)**: this script export a Ghidra project in gzf format. It can be used from the GUI or in headless mode.