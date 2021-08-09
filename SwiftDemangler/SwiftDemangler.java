// This script demangle swift function names using ghidra2frida bridge, 
// running the demangling code directly on the mobile iOS device. The  
// Java code is based on Ghidra Ninja swift_demangler.py 
// (https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py)
// @author Federico Dotta
// @category iOS
// @keybinding
// @menupath Tools.SwiftDemangler
// @toolbar 


/*
 * SwiftDemangler - Demangle Swift functions with ghidra2frida (with service import)
 *
 * Tested with Ghidra v10.0.1
 */


import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

import ghidra2frida.Ghidra2FridaService;

public class SwiftDemangler extends GhidraScript {
	
	Ghidra2FridaService ghidra2FridaService;
	
	boolean debug=false;
	
	public String callGhidra2FridaFunction(String name, String[] parameters) throws Exception {
		
		if(ghidra2FridaService == null)
			ghidra2FridaService = state.getTool().getService(Ghidra2FridaService.class);
		
		return ghidra2FridaService.callExportedFunction("demangle",parameters);		
		
	}
	
	@Override
	protected void run() throws Exception {
		
		FunctionManager functionManager = currentProgram.getFunctionManager();
		
		for(FunctionIterator fns = functionManager.getFunctions(true); fns.hasNext(); ) {
			
			Function f = fns.next();
			
			String f_name = f.getName();
			
			//println(f_name);
			
			// Is it a mangled name?
			if(!(f_name.startsWith("_$") || f_name.startsWith("$s") || f_name.startsWith("_T") || f_name.startsWith("__T")))
				continue;
			
			if(f_name.startsWith("__T"))
				f_name = f_name.substring(1);
			
			
			String previous_comment = f.getComment();
		    if(previous_comment == null)
		        previous_comment = "";

		    try {
		    			    
			    String signature_full = callGhidra2FridaFunction("demangle",new String[] {f_name});
			    
			    String signature = signature_full;
			    
			    if(debug)
			    	println("Mangled: " + f_name + ", Demangled: " + signature_full);
			    			    
			    // Add newlines into full comment (maximum comment len = 58, afterwards truncated)
			    int lines = signature_full.length() / 58;
			    for(int l=1; l < lines+1; l++) 
			        signature_full = signature_full.substring(0, (l*58)+(l-1)) + "\n" + signature_full.substring((l*58)+(l-1));
	
			    f.setComment(previous_comment + "\n" + signature_full);
			    
			    
		    } catch(Exception e) {
		    	
		    	printerr("* Error with method: " + f_name + ". Skipping. Exception:");
		    	printerr(e.toString());
		    	continue;
		    	
		    }
		    
			
		}
		
	}
}
