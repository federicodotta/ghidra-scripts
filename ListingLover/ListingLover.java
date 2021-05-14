//This script copies pseudocode to disassembly listing as comment in order
//to speed up reversing activities.
//@author Federico Dotta
//@category Update
//@keybinding SLASH
//@menupath Tools.ListingLover
//@toolbar

/*
 * ListingLover 1.0
 * 
 * ListingLover is a simple Ghidra script that copies pseudocode to disassembly 
 * listing as comments, like IDA Pro feature reachable from the '/' key. Unlike 
 * IDA, pseudocode is inserted as POST comment and follows related disassembly 
 * instructions. POST comments are perfect for this purpose, because by default 
 * they are shown in the disassembly listing and not in the decompiler pane, 
 * avoiding filling this pane with duplicate data. While IDA Pro instantly adds 
 * the pseudocode to the disassembly listing (probably because the pseudocode 
 * data is already associated to the disassembly listing internally), in Ghidra 
 * I have to scroll all disassembly, decompile every function and add all needed 
 * comments to the disassembly listing. These operations may require a lot of time, 
 * especially when reversing huge binaries. Based on some tests I did, ListingLover 
 * requires an amount of time comparable to that spent during initial analysis. The 
 * plugin can be used also to remove those comments, once added, but it is advisable 
 * to hide POST comments instead of removing ListingLover comments, in order to avoid
 *  wasting time.
 *  
 *  Tested with Ghidra v9.2.3.
 * 
 * Usage (GUI mode):
 * - Auto analyze your target binary with the default analyzers (at least)
 * - Copy the script into your ghidra_scripts directory
 * - Open the Script Manager in Ghidra and run the script
 * - You can also run it via the Tools > ListingLover menu or the shurtcut "/"
 * 
 * Usage (headless mode): 
 * - Launch analyzeHeadless with -postScript ListingLover.java
 * 
 *  Tested with Ghidra v9.2.3.
 */

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

public class ListingLover extends GhidraScript {
	
	public static boolean debug = false;

	@Override
	protected void run() throws Exception {
		
		List<String> choices = new ArrayList<String>(List.of("Add","Remove"));

		FunctionManager functionManager = currentProgram.getFunctionManager();		
		FunctionIterator functionIterator = functionManager.getFunctions(true);
		
		String userChoice;
		if(SystemUtilities.isInHeadlessMode()) {
			
			String[] args = getScriptArgs();
						
			if(args.length > 0) {
				userChoice = args[0];
				
				if( ! choices.stream().anyMatch(c -> c.equalsIgnoreCase(userChoice.trim())) ) {
					
					printf("*** Command not supported. Valid values are %s\n", String.join(", ", choices) );	
					return;
					
				}			
				
			} else {				
				
				printf("*** User did not supply any command. Defaulting to \"Add\"\n");			
				userChoice = "Add";
				
			}
			
		} else {
			
			try {
				
				userChoice = askChoice("Add or remove?", "Do you want to add or remove the decompilation comments?", choices, "Add");
				
			} catch(CancelledException e) {
				
				printf("*** User did not supply any command. Aborting...\n");			
				return;
				
			}
			
		}
		
		long startTime = System.nanoTime();
		
		printf("*** User choice: %s\n",userChoice.trim());
		
		if(userChoice.trim().equalsIgnoreCase("Add")) {
			
			printf("*** ListingLover: adding pseudocode as POST comments to disassembly listing...\n");	
		
			DecompInterface decompInterface = new DecompInterface();
			decompInterface.setOptions(new DecompileOptions());
			
			
			if(decompInterface.openProgram(currentProgram)) {
				
				Function currentFunction;
				while(functionIterator.hasNext()) {
					
					// Check if user aborted from Ghidra GUI
					checkIfUserAborted();
					
					currentFunction = functionIterator.next();
					
					if(debug)
						printf("Current function: %s\n", currentFunction.getName());
					
					DecompileResults decompileResults = decompInterface.decompileFunction(currentFunction, 600 , monitor);
					
					ClangTokenGroup clangTokenGroup = decompileResults.getCCodeMarkup();
					
					if(clangTokenGroup != null) {
					
						printNode(clangTokenGroup,0);
						
					}
					
				}
				
			}
			
		} else {			
			
			printf("*** ListingLover: removing pseudocode as POST comments from disassembly listing...\n");
			
			Listing listing = currentProgram.getListing();
			
			Function currentFunction;
			while(functionIterator.hasNext()) {

				// Check if user aborted from Ghidra GUI
				checkIfUserAborted();
				
				currentFunction = functionIterator.next();
				
				if(debug)
					printf("Current function: %s\n", currentFunction.getName());
				
				AddressSetView adv = currentFunction.getBody();
				
				CodeUnitIterator cui = listing.getCodeUnits(adv, true);
				
				CodeUnit currentCodeUnit;
				while(cui.hasNext()) {
					
					// Check if user aborted from Ghidra GUI
					checkIfUserAborted();
					
					currentCodeUnit = cui.next();
					
					String cur = currentCodeUnit.getComment(CodeUnit.POST_COMMENT);
					
					if (cur != null) {
						
						// append tag to plate comment if not present already
						String comments[] = currentCodeUnit.getCommentAsArray(CodeUnit.POST_COMMENT);
												
						List<String> newComments = new ArrayList<String>();
						for (int i = 0; i < comments.length; i++) {
							if (!(comments[i].startsWith("DEC:"))) {
								newComments.add(comments[i]);
							}
						}
						currentCodeUnit.setCommentAsArray(CodeUnit.POST_COMMENT, newComments.stream().toArray(String[]::new));
												
						
					}
					
				}
				
				
			}
			
			
		}
		
		long endTime = System.nanoTime();
		
		long duration = TimeUnit.SECONDS.convert((endTime - startTime), TimeUnit.NANOSECONDS);
		
		printf("*** ListingLover finished correctly. Computation time: %s seconds\n", String.valueOf(duration));
		
	}
	
	// Check if user aborted from Ghidra GUI	
	public void checkIfUserAborted() {		
		try {
			monitor.checkCanceled();
		} catch (CancelledException e) {
			println("User aborted");
			throw new RuntimeException("User aborted");
		}
	}
	
	public boolean printNode(ClangNode currentNode, int recursionLevel) {
		
		// Check if user aborted from Ghidra GUI
		checkIfUserAborted();
		
		if(currentNode.numChildren() > 0 && currentNode.getMaxAddress() != null) {		
			
			int numberOfNonLeafChildren = 0;
			
			for(int k=0;k<currentNode.numChildren();k++) {
				if(printNode(currentNode.Child(k), recursionLevel+1)) {
					numberOfNonLeafChildren++;
				}
			}
			
			if(numberOfNonLeafChildren == 0) {
			
				String decompiledString = currentNode.toString();
				
				addPostCommentToInstruction("DEC: " + decompiledString, "DEC:", currentNode.getMaxAddress(), true);
				
				
			}
			
			return true;
			
		} else {
			
			return false;
			
		}
		
	}
	
	
	public void addPostCommentToInstruction(String comment, String prefixToCheck, Address addressInstruction, boolean replaceIfAlreadyPresent) {
		
		Instruction instruction = getInstructionAt(addressInstruction);
		
		if(instruction != null) {
			
			if(debug)
				printf("Line: %s, address: %s\n", comment, addressInstruction.toString());
		
			String cur = instruction.getComment(CodeUnit.POST_COMMENT);
			
			if (cur == null) {
				
				instruction.setComment(CodeUnit.POST_COMMENT, comment);
				
			} else {
			
				// append tag to plate comment if not present already
				String comments[] = instruction.getCommentAsArray(CodeUnit.POST_COMMENT);
				boolean potentialClassesCommentAlreadyPresent = false;
				for (int i = 0; i < comments.length; i++) {
					if (comments[i].startsWith(prefixToCheck)) {
						
						// Replace the comment with the new one
						comments[i] = comment;	
						potentialClassesCommentAlreadyPresent = true;
						break;
					}
				}
				
				if( potentialClassesCommentAlreadyPresent) {
					
					if(replaceIfAlreadyPresent)
						instruction.setCommentAsArray(CodeUnit.POST_COMMENT, comments);
					
				} else {
					instruction.setComment(CodeUnit.POST_COMMENT, cur + "\n" + comment);
				}
				
			}
		
		} else {
			
			if(debug)
				printf("Skipping (null instruction). Line: %s, address: %s\n", comment, addressInstruction.toString());
			
		}
			
	}
}
