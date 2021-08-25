# SwiftDemangler

SwiftDemangler demangles swift function names using ghidra2frida bridge, executing the demangling code directly on the mobile iOS device. The output is added to a plate comment on all the Swift functions of the binary. The code is based on Ghidra Ninja swift_demangler.py (https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py) and the Frida demangle code has been taken from https://codeshare.frida.re/@neil-wu/fridaswiftdump/.

The script is supplied in three different versions:

1. SwiftDemangler.java: Ghidra script in Java
2. swift_demangler.java: Ghidra script in Python
3. SwiftDemangler2.java: Ghidra script in Java that uses Java reflection (more details in the article in the references)

Tested with Ghidra v10.0.1.

## Usage

1.	Open target binary and auto analyze it with the default analyzers (at least)
2.	Install ghidra2frida plugin, configure it properly using supplied ghidra2fridaDemangle.js as "Frida JS file", run Pyro server and spawn/attach to target application
3.	Copy the SwiftDemangler script into your ghidra_scripts directory
4.	Open the Script Manager in Ghidra and run the script
5.	Swift demangling output is put as plate comment to Swift functions

## Author
- Federico Dotta -  Principal Security Analyst at HN Security

## References
- [ghidra2frida - The new bridge between Ghidra and Frida](https://security.humanativaspa.it/ghidra2frida-the-new-bridge-between-ghidra-and-frida/)