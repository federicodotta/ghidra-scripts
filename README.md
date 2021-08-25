# ghidra-scripts
[![](https://img.shields.io/github/stars/federicodotta/ghidra-scripts.svg?color=yellow)](https://github.com/federicodotta/ghidra-scripts)
[![](https://img.shields.io/github/forks/federicodotta/ghidra-scripts.svg?color=green)](https://github.com/federicodotta/ghidra-scripts)
[![](https://img.shields.io/github/issues-raw/federicodotta/ghidra-scripts.svg?color=red)](https://github.com/federicodotta/ghidra-scripts/issues)
[![](https://img.shields.io/badge/license-MIT%20License-red.svg?color=lightgray)](https://opensource.org/licenses/MIT) 
[![](https://img.shields.io/badge/twitter-apps3c-blue.svg)](https://twitter.com/apps3c)

A collection of my Ghidra scripts.

## iOS	
* **[FOX](https://github.com/federicodotta/ghidra-scripts/tree/master/FOX/)**: This script locates all calls to *objc_msgSend* family functions, tries to infer the actual method that gets referenced, and adds cross-references, potential cross-references and useful comments.
* **[SwiftDemangler](https://github.com/federicodotta/ghidra-scripts/tree/main/SwiftDemangler)**: This script demangles swift function names using ghidra2frida bridge, executing the demangling code directly on the mobile iOS device.

## Misc
* **[ListingLover](https://github.com/federicodotta/ghidra-scripts/tree/master/ListingLover/)**: this script adds the pseudocode as comment to the disassembly listing. It can be used from the GUI or in headless mode.
* **[ExportToGzf](https://github.com/federicodotta/ghidra-scripts/tree/master/ExportToGzf/)**: this script exports a Ghidra project in gzf format. It can be used from the GUI or in headless mode.