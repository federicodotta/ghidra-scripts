#This script demangle swift function names using ghidra2frida bridge, 
#running the demangling code directly on the mobile iOS device. The  
#code is based on Ghidra Ninja swift_demangler.py 
#(https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py)
#@author Federico Dotta
#@category iOS
#@keybinding
#@menupath Tools.SwiftDemangler
#@toolbar 

from ghidra.program.model.symbol import SourceType

from ghidra2frida import Ghidra2FridaService

debug_mode = False

ghidra2FridaService = None

def callGhidra2FridaFunction(name, parameters):
    global ghidra2FridaService
    if ghidra2FridaService is None:
        ghidra2FridaService = state.getTool().getService(Ghidra2FridaService)
        println("ghidra2FridaService initialized")

    return ghidra2FridaService.callExportedFunction(name,parameters);

println("ghidra2frida demangle START")

functionManager = currentProgram.getFunctionManager()

# Get functions in ascending order
fns = functionManager.getFunctions(True)
for f in fns:
    f_name = f.getName()

    if debug_mode:
        println("Processing " + f_name)

    # Is it a mangled name?
    if not (f_name.startswith("_$") or f_name.startswith("$s") or f_name.startswith("_T") or f_name.startswith("__T")):
        continue

    if f_name.startswith("__T"):
        f_name =  f_name[1:]        

    previous_comment = f.getComment()

    try:

        signature_full = callGhidra2FridaFunction("demangle",[f_name]);

        if debug_mode:
            println("Demangle output: " + signature_full)

        # Add newlines into full comment (maximum comment len = 58, afterwards truncated)
        lines = len(signature_full) / 58
        for l in range(1, lines+1):
            signature_full = signature_full[:(l*58)+(l-1)] + "\n" + signature_full[(l*58)+(l-1):]

        if not previous_comment:
            f.setComment(signature_full)
        else:    
            f.setComment(previous_comment + "\n" + signature_full)
        
    except Exception as exc:
        printerr("Error with method: " + f_name + ". Skipping. Exception:")    
        printerr(str(exc))


println("ghidra2frida demangle END")