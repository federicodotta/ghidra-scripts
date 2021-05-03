//This script pack the project in a gzf archive. Based on beigela post on GitHub. 
//@author Federico Dotta
//@category Export
//@keybinding E
//@menupath Tools.ExportToGzf
//@toolbar

/*
 * ExportToGzf 1.0
 * 
 * ExportToGzf is a simple Ghidra script that can be used to export a Ghidra
 * project in gzf format. An exported project can be then imported by creating
 * a new Ghidra project and selecting the "Import file..." option. The plugin
 * can be used in GUI and in headless mode, but it is more useful in this last
 * mode because at the current version of Ghidra it is not possible to export
 * a project.
 * 
 * Based on beigela python script posted here:
 * https://github.com/NationalSecurityAgency/ghidra/issues/2104
 * 
 * Usage (headless mode): 
 * - Launch analyzeHeadless with -postScript ExportToGzf.java #OUTPUT_PATH
 * - If #OUTPUT_PATH parameter is not supplied, the gzf is saved in the 
 *   ghidraProject.gzf file of current directory
 * 
 * Usage (GUI mode):
 * - Copy the script into your ghidra_scripts directory
 * - Open the Script Manager in Ghidra and run the script
 * - You can also run it via the Tools > ExportToGzf menu or the shurtcut "E"
 * 
 *  Tested with Ghidra v9.2.3.
 */

import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

public class ExportToGzf extends GhidraScript {

	// Conversion in Java of beigela python script posted here
	// https://github.com/NationalSecurityAgency/ghidra/issues/2104
	
	@Override
	protected void run() throws Exception {

		String outputPath;
		
		if(SystemUtilities.isInHeadlessMode()) {			
			String[] args = getScriptArgs();
			if(args.length > 0) {
				outputPath = args[0];
				printf("*** Archive output path: %s\n",outputPath);		
			} else {
				outputPath = "ghidraProject.gzf";
				printf("*** Output path not supplied. Output in the current directory, filename: %s\n",outputPath);	
			}			
		} else {
			try {			
				outputPath = askString("Please enter the path","Please enter the output path for the archive").trim();
			} catch(CancelledException e) {				
				printf("*** Output path not supplied. Quitting.\n");			
				return;				
			}			
		}		
		
		Program program = getCurrentProgram();
		DomainFile domainFile = program.getDomainFile();
		File outFile = new File(outputPath);
		end(true);
		domainFile.packFile(outFile, monitor);		
		
	}
}
