// This script locates all calls to *objc_msgSend* family functions, tries to
// infer the actual method that gets referenced, and adds cross-references, 
// potential cross-references and useful comments. 
// @author Federico Dotta and Marco Ivaldi
// @category iOS
// @keybinding X
// @menupath Tools.FOX
// @toolbar 


/*
 * FOX 1.0 - Fix Objective-C XREFs in Ghidra
 * Copyright (c) 2021 Federico Dotta and Marco Ivaldi
 *
 * "When it encounters a method call, the compiler generates a call to one of
 * the functions objc_msgSend, objc_msgSend_stret, objc_msgSendSuper, or
 * objc_msgSendSuper_stret. Messages sent to an object's superclass (using the
 * super keyword) are sent using objc_msgSendSuper; other messages are sent
 * using objc_msgSend. Methods that have data structures as return values are
 * sent using objc_msgSendSuper_stret and objc_msgSend_stret." 
 * 					-- Apple Objective-C Documentation
 *
 * FOX is a Ghidra script to assist with reverse engineering of iOS apps. 
 * It locates all calls to *objc_msgSend* family functions, tries to
 * infer the actual method that gets referenced, and updates cross-references
 * accordingly. If the inferred *objc_msgSend* argument matches more than one
 * method, it tries to determine the class of the called method. When this is
 * not possible, it instead adds a plate comment to all potentially referenced
 * methods that can be then checked manually, to avoid polluting the project
 * with bogus XREFs. Furthermore, a PRE comment is added to all the msgSend
 * calls to speed-up reversing activities. It can use the output of a Frida
 * script to produce better result, using a list of all the objC functions
 * available to the binary, including the ones residing outside the binary
 * currently analyzed (es. system libraries, other binaries of the IPA, etc.)
 *
 * Usage (GUI mode):
 * - Auto analyze your target binary with the default analyzers (at least)
 * - Copy the script into your ghidra_scripts directory
 * - Open the Script Manager in Ghidra and run the script
 * - You can also run it via the Tools > FOX menu or the shurtcut "X"
 * - Optionally supply the output of the attached Frida script when requested 
 * - Navigate newly updated XREFs, PRE and plate comments, if applicable
 *
 * Usage (headless mode):
 * - Launch analyzeHeadless with -postScript FOX.java
 * - Optionally supply the output of the attached Frida script after the script 
 *   name (ex. -postScript FOX.java fridaOutput.txt)
 * - Navigate newly updated XREFs, PRE and plate comments, if applicable
 *
 * Caveats:
 * - The list of *objc_msgSend* family functions may be incomplete (you can
 *   easily add your own, though)
 * - Large binaries may require a long processing time, but the plugin has
 *   been optimized in order to minimize the times the binary is read 
 *
 * Tested with Ghidra v9.2.3.
 */

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.LinkedList;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class FOX extends GhidraScript {
	
	DecompInterface decompInterface;
	List<String> msgSendFuncsName;
	List<Function> msgSendFuncs;
	Map<String,List<MsgSendInvocationData>> msgSendInvocationsHashMap;
	Map<String,List<MsgSendInvocationData>> functionsOfTheBinary;
	Map<String, List<String>> fridaExternalList;
	List<Function> functionsCallingMsgSend;
	
	static int MAX_POTENTIAL_INTERNAL_XREFS_INLINE = 10;
	static int MAX_POTENTIAL_EXTERNAL_XREFS_INLINE = 10;
	// Increasing too much this value can cause performance drop and in some situations stucks with hige binaries
	static int MAX_POTENTIAL_FUNCTION_XREFS = 20;
	
	// Allowed values 0, 1 and 2
	static int DEBUG_LEVEL = 0;
			
	@Override
	public void run() throws Exception	{
		
		long startTime = System.nanoTime();
						
		msgSendInvocationsHashMap = new TreeMap<String,List<MsgSendInvocationData>>();
		functionsOfTheBinary = new TreeMap<String,List<MsgSendInvocationData>>();		
				
		// *objc_msgSend* family functions
		// CAVEAT: this list may be incomplete
		msgSendFuncsName = new LinkedList<String>(List.of(
			"_objc_msgSend", "_objc_msgSend_stret",
			"_objc_msgSendSuper", "_objc_msgSendSuper_stret",
			"_objc_msgSendSuper2", "_objc_msgSendSuper2_stret"
		));
		msgSendFuncs = new LinkedList<Function>();

		printf("\nFOX 1.0 - Fix Objective-C XREFs in Ghidra\n");
		printf("Attempting to fix Objective-C XREFs...\n\n");
		
		decompInterface = new DecompInterface();
		decompInterface.setOptions(new DecompileOptions());
		
		String methodListPath = null;
		
		// Ask to the user the output of Frida script or take the list from arguments (in headless mode)
		if(SystemUtilities.isInHeadlessMode()) {
			
			String[] args = getScriptArgs();
			
			if(DEBUG_LEVEL >= 1) {
				println("*** DEBUG 1 Script args:");
				Arrays.asList(args).stream().forEach(k -> println(k));
			}			
			
			if(args.length > 0) {
				methodListPath = args[0];
				fridaExternalList = new TreeMap<String, List<String>>();
			} else {
				printf("*** User did not supply external Frida file. Proceeding without it\n");			
				fridaExternalList = null;
			}
			
		} else {
		
			// Ask the user the output of the attached Frida script, for a more accurate result of the Ghidra script
			try {
			
				methodListPath = askString("Please enter the full path","Please enter the full path of the methods list, obtained with Frida. The file il not mandatory but the script will give more accurate results with it").trim();
				
				fridaExternalList = new TreeMap<String, List<String>>();
				
			} catch(CancelledException e) {
				
				printf("*** User did not supply external Frida file. Proceeding without it\n");			
				fridaExternalList = null;
				
			}
			
		}
		
		// If the Frida output is supplied, populate the structure fridaExternalList that will be used by the script
		// That hashmap is indexed by method names and contains all the classes of each method
		
		if(fridaExternalList != null) {
		
			printf("*** Loading Frida input file\n");
			
			try {
			
				BufferedReader reader = new BufferedReader(new FileReader(methodListPath));
				String line = reader.readLine();
				String currentClassName = null;
				while(line != null) {
					
					String cleanedMethodName;
					
					// the current line contains a method signature
					if(line.startsWith("+ ") || line.startsWith("- ")) {
						
						cleanedMethodName = line.substring(2).trim();
						
						// we already have current method in our hashmap
						if(fridaExternalList.containsKey(cleanedMethodName)) {
							
							// if we don't have current class name in the ArrayList indexed by current method name, we add it
							if(!(fridaExternalList.get(cleanedMethodName).contains(currentClassName))) {
								fridaExternalList.get(cleanedMethodName).add(currentClassName);								
							}
							
						// we don't have the current method in our hashmap. We create an ArrayList for him.
						} else {
							
							List<String> newArrList = new LinkedList<String>();
							newArrList.add(currentClassName);
							fridaExternalList.put(cleanedMethodName, newArrList);
							
						}
						
					// the current line contains a class name	
					} else {
						
						// We save current class name in a variable
						
						currentClassName = line.trim();
						
					}
					
					
					line = reader.readLine();
				}
				
			} catch(Exception e) {
				
				printerr("*** EXCEPTION importing Frida list");
				printerr(e.toString());
				StackTraceElement[] excElements = e.getStackTrace();
				for(StackTraceElement el : excElements) {
					printerr(el.toString());
				}
				return;
				
			}
			
			if(DEBUG_LEVEL >= 2) {
				printf("*** DEBUG 2 Frida external list keys\n");
				fridaExternalList.keySet().stream().forEach(k -> printf("%s\n",k));
			}
			
		}
		
		printf("*** Loading input file process finished\n");
		
		// Decompiler initialization
		if(decompInterface.openProgram(currentProgram)) {
		
			// References to common msgSend functions are searched in the symbol table
			printf("*** Findind msgSend functions in the binary\n");
			findObjcMsgSendFunctionsInBinary();
			printf("*** Findind msgSend functions in the binary - DONE\n");
						
			// Functions that calls one of the msgSend functions are retrieved
			printf("*** Getting a list of all functions that call one of the msgSend functions\n");
			findFunctionsCallingMsgSend();
			printf("*** Getting a list of all functions that call one of the msgSend functions - DONE\n");
			
			// Each function that calls a msgSend is then decompiled and analyzed
			// Analysis is executed on the decompiled code in order to benefit from Ghidra analyzers
			printf("*** Decompiling and analyzing the %d functions\n", functionsCallingMsgSend.size());
			int functionsCallingMsgSendSize = functionsCallingMsgSend.size();
			for(int i=0; i< functionsCallingMsgSendSize; i++) {						
			//functionsCallingMsgSend.stream().forEach(f -> {
				
				if(i%100 == 0)
					printf("* Analysing function %d/%d\n",i, functionsCallingMsgSendSize);
											
				//DecompileResults decompileResults = decompInterface.decompileFunction(f, 600 , monitor);
				DecompileResults decompileResults = decompInterface.decompileFunction(functionsCallingMsgSend.get(i), 600 , monitor);
				
				ClangTokenGroup clangTokenGroup = decompileResults.getCCodeMarkup();
				
				if(clangTokenGroup != null) {
				
					// Recursive method that processes the tree created by Ghidra decompiler
					// and populate an the structures used by the addXrefs function
					printNode(clangTokenGroup,0);
					
				}
						
			}		
			//});
			printf("*** Decompiling and analyzing the functions - DONE\n");
			
			// This function creates an HashMap that contains all the functions of the binary that share the name of one of the msgSend arguments
			printf("*** Creating a list of all functions of the binary\n");
			populateListOfBinaryFunctions();
			printf("*** Creating a list of all functions of the binary - DONE\n");
						
			// This function uses all the structures created before and adds XREFs, pontential XREFs and comment on calling functions, in order
			// to speed up and simplify reversing effort
			printf("*** Adding XREFs\n");
			addXrefs();
			printf("*** Adding XREFs - DONE\n");
			
			/*		
			// DEBUG - Executing the plugin on a single function (supplying address) for debug purposes
			Function currentFunction = currentProgram.getFunctionManager().getFunctionAt(currentProgram.getAddressFactory().getAddress("10000aad0"));
					
			DecompileResults decompileResults = decompInterface.decompileFunction(currentFunction, 600 , monitor);
					
			ClangTokenGroup clangTokenGroup = decompileResults.getCCodeMarkup();
			//printf("ToString: %s\n", clangTokenGroup.toString());
			//printf("numChildren: %d\n", clangTokenGroup.numChildren());
				
			printNode(clangTokenGroup,0);
					
			addXrefs();
			*/
			
			
		}
		
		long endTime = System.nanoTime();
		
		long duration = TimeUnit.SECONDS.convert((endTime - startTime), TimeUnit.NANOSECONDS);
		
		printf("*** FOX finished correctly. Computation time: %s seconds\n", String.valueOf(duration));
					
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
	
	// This function search in the symbol table for obj_msgsend functions and adds the found ones to the msgSendFuncs HashMap	
	public void findObjcMsgSendFunctionsInBinary() {
		
		msgSendFuncsName.stream().forEach(fn -> {
			
			// Check if user aborted from Ghidra GUI
			checkIfUserAborted();
		
			// We get a symbol iterator over each of our msgSend functions
			SymbolTable st = currentProgram.getSymbolTable();
			SymbolIterator si = st.getSymbolIterator(fn,true);
						
			while (si.hasNext()) {
				
				// Check if user aborted from Ghidra GUI
				checkIfUserAborted();
				
				Symbol s = si.next();
				if ((s.getSymbolType() == SymbolType.FUNCTION) && (!s.isExternal()) && (s.getName().equals(fn))) {
					
					Function currentMsgFunc = getFunctionAt(s.getAddress());
					
					// Non thunk functions are skipped					
					if(currentMsgFunc.isThunk()) {
					
						msgSendFuncs.add(getFunctionAt(s.getAddress()));
						printf("*** FOUND function %s, address %s, parent name %s\n", fn, s.getAddress(), getFunctionAt(s.getAddress()).getParentNamespace().getName());
						
					} else {
						
						if(DEBUG_LEVEL >= 1)
							printf("*** DEBUG 1 skipping non-thunk %s function\n", fn);
						
					}
						
				}
			}
			
		});
		
	}
	
	// This method populate a list of all the functions that call one or more times one of the msgSend functions.
	// This list is used to avoid decompiling functions that don't call any msgSend function, in order to optimize the performances.
	public void findFunctionsCallingMsgSend() {
		
		List<Function> tempFunctionsCallingMsgSend = new LinkedList<Function>();
		
		// We search in the code for all the references to the msgSend functions found previously in the binary (dstFunctions)
		// We process each msgSend function found previously in the binary (dstFunctions)
		for(Function dstFunc : msgSendFuncs) {
			
			// Check if user aborted from Ghidra GUI
			checkIfUserAborted();
			
			// get XREFs
			// the getReferencesTo() method of the FlatProgramAPI is limited to 4096 records
			// for this reason this script uses ReferenceManager::getReferencesTo() instead
			Address dstAddr = dstFunc.getEntryPoint();
			ReferenceManager refman = currentProgram.getReferenceManager();
			ReferenceIterator ri = refman.getReferencesTo(dstAddr);
			
			// For each msgSend function, we iterate over all the references in the code to that msgFunction
			// The purpose is to get a list of all functions of the binary that execute a msgSend call (functionsContainingMsgSends)
			while (ri.hasNext()) {
				
				// Check if user aborted from Ghidra GUI
				checkIfUserAborted();				
				
				Reference ref = ri.next();

				if (ref.getReferenceType().isCall()) {
					Address callAddr = ref.getFromAddress();
					Function srcFunc = getFunctionContaining(callAddr);

					if ((srcFunc != null) && (!srcFunc.isThunk())) {
						
						tempFunctionsCallingMsgSend.add(srcFunc);
											
					}
				}
			}
			
		}
		
		// Remove duplicates from the list
		functionsCallingMsgSend = new LinkedList<Function>();				
		AddressFactory af = getAddressFactory();
		tempFunctionsCallingMsgSend.stream().map(Function::getEntryPoint).map(Address::toString).distinct()
										  .forEach(o -> functionsCallingMsgSend.add(getFunctionAt(af.getAddress(o))));
		
		/* DEBUG
		println("*** Functions that calls msgSend with duplicates"); 
		tempFunctionsCallingMsgSend.stream().forEach(f -> println("" + f.getEntryPoint().toString()));
		println("*** Functions that calls msgSend without duplicates");
		functionsCallingMsgSend.stream().forEach(f -> { if(f.getEntryPoint() != null) println("" + f.getEntryPoint().getOffset()); else println("NULL");});
		functionsCallingMsgSend.stream().forEach(f -> println("" + f.getEntryPoint().toString())); */		
		
	}
	
	// PrintNode return false if the node is a leaf OR a node without address (and we are not interested in continue recursion on these nodes...)
	// and return true if the node is not a leaf AND has an address.
	// If all the children of a node are leafs or without addresses we are in the level we are interested in and we populate the structures
	// that we will use in the addXrefs function.
	// The nodes we are searching for contain to the decompiled instructions before each being divided into multiple lines to fit into the Ghidra decompiler pane
	// (there is not so much documentation on these decompiler structures, so I made some tries before finding the right node...)
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
				
				if(DEBUG_LEVEL >= 2)
					printf("*** DEBUG 2 Node: %s, Recursion: %d, MinAddress: %s, MaxAddress: %s\n", currentNode.toString(), recursionLevel, currentNode.getMinAddress(), currentNode.getMaxAddress());
				
				List<String> matches = new LinkedList<String>();
				
				// We process the decompiled instruction if contains one of the msgSend method name
				if(msgSendFuncsName.stream().anyMatch(f -> currentNode.toString().contains(f))) {
								
					Matcher m = Pattern.compile("(" + msgSendFuncsName.stream().collect(Collectors.joining( "|" )) + ")\\s*\\((.*?),(.*?)[,)]{1}.*")
									   .matcher(currentNode.toString());
					
			        while(m.find()) {
			            matches.add(m.group(1));
			            matches.add(m.group(2));
			            matches.add(m.group(3));
			            
			            if(DEBUG_LEVEL >= 1) {
			            	print("*** DEBUG 1 Adding a msgSend call. Details:\n"); 
				            printf("msgSend function name: %s, ",m.group(1));
				            printf("Called class: %s, ",m.group(2));
				            printf("Called function: %s, ",m.group(3));
				            printf("Address: %s\n",currentNode.getMaxAddress().toString());
			            }
			            
			            String className = getClassName(m.group(2).trim());
			            
			            String functionName = m.group(3).trim();
			            
			            // If the Ghidra decompiler didn't retrieve the function name of the msgSend call, we skip the reference. If there is the name, it starts with a double quote "
			            // Maybe we could also process msgSend call in witch we have the class name without the function name, adding potential entries,
			            // but the binary would become a mess...
			            if(functionName.startsWith("\"")) {
			            				            	
			            	// Remove leading and trailing "
			            	functionName = functionName.substring(1, functionName.length()-1).trim();
			            	
			            	// If it is the first time we process a function with that function name, we create a List in our HashMap indexed by that function name
			            	if(!msgSendInvocationsHashMap.containsKey(functionName)) {
			            		
			            		msgSendInvocationsHashMap.put(functionName,new LinkedList<MsgSendInvocationData>());
			            		
			            	}
			            	
			            	// Then we save details on that call (function name, class name and address) using a custom object
			            	msgSendInvocationsHashMap.get(functionName).add(new MsgSendInvocationData(functionName,currentNode.getMaxAddress(),className));
			            				            	
			            }
			            
			        }
			        
				}
			
			}	
			return true;
				
		} else {
			
			return false;
			
		}
	}
	
	// This method popuplate a list (pratically a HashMap) of all the functions of the binary (retrieved from the Symbol Table) with the same method name of one of the msgSend found in the steps
	// The purpose of this list is to optimize the sequent steps
	public void populateListOfBinaryFunctions() {
		
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator si = st.getSymbolIterator();
		
		while (si.hasNext()) {
			
			// Check if user aborted from Ghidra GUI
			checkIfUserAborted();
			
			Symbol s = si.next();
			
			if (s.getSymbolType() == SymbolType.FUNCTION && !s.isExternal()) {
				
				String currentFunctionName = s.getName().trim();
				
				if(DEBUG_LEVEL >= 2)
					printf("*** DEBUG 2 - Current symbol %s, address %s\n", currentFunctionName, s.getAddress().toString());
				
				if(msgSendInvocationsHashMap.containsKey(currentFunctionName)) {
					
					if(DEBUG_LEVEL >= 1)
						printf("*** DEBUG 1 - Adding %s to functionsOfTheBinary HashMap\n", currentFunctionName);
					
					if(!functionsOfTheBinary.containsKey(currentFunctionName)) {
						functionsOfTheBinary.put(currentFunctionName, new LinkedList<MsgSendInvocationData>());
					}
					
					String classNameOfCurrentFunction = getFunctionAt(s.getAddress()).getParentNamespace().getName().trim();
					functionsOfTheBinary.get(currentFunctionName).add(new MsgSendInvocationData(currentFunctionName,s.getAddress(),classNameOfCurrentFunction));
					
				}
				
			}
		
		}
				
	}
		
	// This method uses the structures made at the previous step to cycle through all the msgSend contained in the binary adding XREFs (when we have the class name in
	// the decompiled code or a single function with that called function name) and POTENTIAL XREFs (when we dont' have the class name and we have multiple functions
	// with the same method name). In all the situations, a PRE-comment is added to the msgSend call with all the information we have (class, method, address), in order
	// to speed-up reversing activities, helping specially reversers that uses mainly the disassembly pane.
	public void addXrefs() {
		
		// We use this variable as index to show progress. We can't use a simple integer becasue we will use Java streams
		AtomicInteger currentFunctionIndex = new AtomicInteger(0);
		
		// keys of msgSendInvocationsHashMap are all the function names of the msgSend invocations of the binaries		
		int functionNameNumber = msgSendInvocationsHashMap.keySet().size();
		printf("*** Add XREF - Processing %d function names", functionNameNumber);
		for (String key : msgSendInvocationsHashMap.keySet()) {
			
			if(currentFunctionIndex.incrementAndGet() % 100 == 0)
				printf("* Processing function name %d/%d\n", currentFunctionIndex.get(), functionNameNumber);
			
			// We get a list of MsgSendInvocationData objects that includes data of all the msgSend invocation of the binary that calls a function with the name
			// of the current key (without considering the class at the moment)
			List<MsgSendInvocationData> currentFunctionsToCheck = msgSendInvocationsHashMap.get(key);
			
			if(DEBUG_LEVEL >=2) {
				printf("*** DEBUG 2 currentFunctionToCheck size %d, elements:\n", currentFunctionsToCheck.size());
				currentFunctionsToCheck.stream().forEach(d -> printf("Element %s %s\n", d.getClassName(),d.getFunctionName()));
			}
			
			AtomicInteger currentFunctionsToCheckSize = new AtomicInteger(currentFunctionsToCheck.size());
			currentFunctionsToCheck.forEach(fc -> {
				
				// Check if user aborted from Ghidra GUI
				checkIfUserAborted();
								
				// If the msgSend we are processing contains also the className (because Ghidra decompiler successfully retrieve that information)
				if(fc.getClassName() != null) {					
					
					Address methodAddressForComment = null;
					
					// We get the list of binary functions with the same name
					if(functionsOfTheBinary.containsKey(key)) {
						
						List<MsgSendInvocationData> currentFunctionsOfTheBinary = functionsOfTheBinary.get(key);
						
						if(DEBUG_LEVEL >= 2) {
							printf("*** DEBUG 2 CurrentFunctionsOfTheBinary size %d. Elements\n", currentFunctionsOfTheBinary.size());
							currentFunctionsOfTheBinary.stream().forEach(d -> printf("Element %s %s\n", d.getClassName(),d.getFunctionName()));
						}
					
						if(currentFunctionsOfTheBinary != null) {
						
							// We loop in the function list looking at a function with the same className
							for(MsgSendInvocationData fb : currentFunctionsOfTheBinary) {
								
								// Check if user aborted from Ghidra GUI
								checkIfUserAborted();
																							
								// If we find a function with the same className (and the same method name) we add an XREF
								if(fb.getClassName().equals(fc.getClassName())) {
									
									if(DEBUG_LEVEL >= 1)
										printf("*** DEBUG 1 Adding XREF with Class from %s to %s, function name %s, function class %s\n", fb.getAddress().toString(), fc.getAddress().toString(), key, fb.getClassName());
									
									// This if condition probably is useless...
									if(!(getSymbolAt(fb.getAddress()).isExternal())) { 

										addInstructionXref(fc.getAddress(), fb.getAddress(), -1, FlowType.UNCONDITIONAL_CALL);
										
										methodAddressForComment = fb.getAddress();
										
									} 
									
									break;
									
								}							
								
								
							}
							
						}
						
					}
					
					// In both cases (if we find in the binary a function with the same class and method name or not) a pre-comment 
					// is added to the objMsgSend call that simplifies the reversing process when working on the dissassembly
					addPreComment(fc.getAddress(),fc.getClassName(),fc.getFunctionName(),methodAddressForComment);
					
				
				// The Ghidra decompiler msgSend invocation did not include the className but only the methodName (we skip entries without methodName)
				} else {
					
					// If the frida external list has been supplied, the HashMap that contains that list contains an entry with the same method name of the one we are 
					// currently processing and that entry contains only one element -> probably we found the missing className (because frida list includes all the internal
					// and external methods)
					if(fridaExternalList != null && fridaExternalList.containsKey(key) && fridaExternalList.get(key).size() == 1) {
					
						// We take the only class name related to the method name
						String classNameForComment = fridaExternalList.get(key).get(0);
												
						Address methodAddressForComment = null;
						
						// If that function is present in the binary INTERNAL function, given that there is only one class with that function, we can add an XREF	
						if(functionsOfTheBinary.containsKey(key)) {
							
							List<MsgSendInvocationData> currentFunctionsOfTheBinary = functionsOfTheBinary.get(key);
														
							// This check is partially redundant but it is better to have one more check than one less...
							if(currentFunctionsOfTheBinary != null && currentFunctionsOfTheBinary.size() == 1 && 
									!(getSymbolAt(currentFunctionsOfTheBinary.get(0).getAddress()).isExternal())) { 
								
								if(DEBUG_LEVEL >= 1)
									printf("*** DEBUG 1 Adding XREF with Class (only 1 match) from %s to %s, function name %s, function class %s\n", 
										currentFunctionsOfTheBinary.get(0).getAddress().toString(), fc.getAddress().toString(), key, currentFunctionsOfTheBinary.get(0).getClassName());
								
								// Add XREF to fc with class
								addInstructionXref(fc.getAddress(), currentFunctionsOfTheBinary.get(0).getAddress(), -1, FlowType.UNCONDITIONAL_CALL);
								
								// If I found the function internal in the, I take the class name from the binary, because Swift mangling on Swift bridge methods
								// can cause different names between Frida and Ghidra class names								
								classNameForComment = currentFunctionsOfTheBinary.get(0).getClassName();								
								methodAddressForComment = currentFunctionsOfTheBinary.get(0).getAddress();
								
							} 
							
						}
						
						// In both cases (if the function was internal or external to the binary) a pre-comment 
						// is added to the objMsgSend call that simplifies the reversing process when working on the dissassembly
						addPreComment(fc.getAddress(),classNameForComment,key,methodAddressForComment);
						
					// If the frida list has not been supplied OR if it includes more classes that contain a method with the name we are currently processing	
					// we can only add some POTENTIAL xrefs as PLATE comment, but we could not add a confident XREF as in the step before
					} else {
						
						// If we have in the binary one or more methods with the name we are processing, we add a POTENTIAL XREF as plate comment to all of them.
						// If we have too much functions with the same name, this comment is useless and consequently we skip it. Pay attention that
						// using a too big value of MAX_POTENTIAL_FUNCTION_XREFS or removing this check can decrease the performance or even stuck the plugin,
						// when working with big binaries...
						if(functionsOfTheBinary.containsKey(key) && currentFunctionsToCheckSize.get() <= MAX_POTENTIAL_FUNCTION_XREFS) { 
							
							List<MsgSendInvocationData> currentFunctionsOfTheBinary = functionsOfTheBinary.get(key);							
						
							if(currentFunctionsOfTheBinary != null) { 
															
								// Add the potential XREF as PLATE comment to all of them
								currentFunctionsOfTheBinary.forEach(fb -> {
									
									// Check if user aborted from Ghidra GUI
									checkIfUserAborted();
									
									// The IF condition is probably useless...
									if(!(getSymbolAt(fb.getAddress()).isExternal())) {
									
										if(DEBUG_LEVEL >= 1)
											printf("*** DEBUG 1 Adding POTENTIAL XREF from %s to %s, function name %s\n", fb.getAddress().toString(), fc.getAddress().toString(), key);
										
										Function functionForPotentialXRef = getFunctionContaining(fc.getAddress());
	
										if(functionForPotentialXRef != null) {
											addPotentialPlateCommentToFunction(getFunctionAt(fb.getAddress()), fc.getAddress(), 
													functionForPotentialXRef.getParentNamespace().getName().trim() + " -> " + functionForPotentialXRef.getName());
										}
																				
									} 
									
								});
								
							} 
							
						} else if(functionsOfTheBinary.containsKey(key)) {
							
							if(DEBUG_LEVEL >= 1)
								printf("*** Skipping function %s, too many references (%d)\n", key, currentFunctionsToCheckSize.get());
							
						}
						
						// In both cases (if we found the method name in the binary or not) a POTENTIAL pre-comment that contains a list of all the 
						// internal and external methods with the same name is added to the objMsgSend call, in order to
						// simplify the reversing process when working on the dissassembly	
						addPontetialPreComment(fc.getAddress(),functionsOfTheBinary.get(key),(fridaExternalList != null ? fridaExternalList.get(key) : null),key,null);
						
							
					}
						
				}
					
			});
			
			
			// Add a "SKIP POTENTIAL XRE comment" to method names with a lot of references, in order to show to the user the methods without references
			if(functionsOfTheBinary.containsKey(key) && currentFunctionsToCheckSize.get() > MAX_POTENTIAL_FUNCTION_XREFS) { 
				
				List<MsgSendInvocationData> currentFunctionsOfTheBinary = functionsOfTheBinary.get(key);
				
				currentFunctionsOfTheBinary.forEach(fb -> {
					
					// Check if user aborted from Ghidra GUI
					checkIfUserAborted();
					
					if(DEBUG_LEVEL >= 1)
						printf("*** DEBUG 1 Adding SKIP POTENTIAL XREF comment to function name %s address %s\n", key, fb.getAddress().toString());
					
					Function curFun = getFunctionAt(fb.getAddress());
					
					String tag = "Potential XREF skipped for this method. Too many references";
					
					appendPlateCommentToFunction(curFun, tag);
					
					/*String cur = curFun.getComment();
					
					if (cur == null) {						
						curFun.setComment(tag);						
					} else {
						// append tag to plate comment if not present already
						String comments[] = curFun.getCommentAsArray();
						for (int i = 0; i < comments.length; i++) {
							if (comments[i].startsWith(tag)) {
								return;
							}
						}
						curFun.setComment(cur + "\n" + tag);						
					}*/
					
					
				});
				
								
			}
						
		}
		
		
	}
	
		
	// Function that parse the className extracted from Ghidra decompiled code
	public String getClassName(String nodeValue) {
		
		String className;
		
		if(nodeValue.contains("objc::")) {
			// ex. &objc::class_t::Helpers
			className = nodeValue.substring(nodeValue.lastIndexOf("::") + 2).trim();
		// DEBUG: comment this "else if" branch to have some potential XREFS for debugging purposes, if the binary does not have any	
		} else if(nodeValue.contains("_OBJC_CLASS")) {
			// ex. &_OBJC_CLASS_$_NSString
			className = nodeValue.substring(15).trim();
		} else {
			if(DEBUG_LEVEL >= 1)
				printf("*** DEBUG 1 Unknown class name %s\n", nodeValue);
			className = null;
		}		
		
		return className;
		
	}
	
	// Append a plate comment to a function to indicate a potential XREF
	public void addPotentialPlateCommentToFunction(Function method, Address addr, String name) {
		
		String tag = "Potential XREF: " + addr.toString() + " " + name;

		appendPlateCommentToFunction(method, tag);
		
	}
	
	// Append a plate comment to a function
	public void appendPlateCommentToFunction(Function method, String comment) {
		
		String cur = method.getComment();
		
		if (cur == null) {
			
			method.setComment(comment);
			
		} else {

			// append tag to plate comment if not present already
			String comments[] = method.getCommentAsArray();
			for (int i = 0; i < comments.length; i++) {
				if (comments[i].startsWith(comment)) {
					return;
				}
			}
			method.setComment(cur + "\n" + comment);
			
		}
		
		
	}
	
	
	// Add a POTENTIAL pre-comment to a msgSend call, that includes two list of potential ObjC method signatures   
	public void addPontetialPreComment(Address addressInstruction, List<MsgSendInvocationData> internalReferences, List<String> externalClassNames, String methodName, Address addressFunction) {
		
		// Preamble
		addPreComment(addressInstruction,null,methodName,addressFunction);
		
		// Internal potential XREFS
		String potentialInternalXrefsForPreComment = null;
		List<String> internalClassNames = null;
		
		
		// Get internal references list
		if(internalReferences != null) {			
			
			potentialInternalXrefsForPreComment = internalReferences.stream().limit(MAX_POTENTIAL_INTERNAL_XREFS_INLINE).map(ir -> ir.getClassName() + " (" + ir.getAddress().toString() + ")").collect(Collectors.joining( ", " ));
			internalClassNames = internalReferences.stream().map(ir -> ir.getClassName()).collect(Collectors.toList());
			
			if(internalReferences.size() > MAX_POTENTIAL_INTERNAL_XREFS_INLINE)
				potentialInternalXrefsForPreComment = potentialInternalXrefsForPreComment + ", ...";
			
		}
		
		String potentialExternalXrefsForPreComment = null;
		
		// Get external references list
		if(externalClassNames != null) {
			
			if(internalClassNames == null || internalClassNames.size() == 0) {
				
				potentialExternalXrefsForPreComment = externalClassNames.stream().limit(MAX_POTENTIAL_EXTERNAL_XREFS_INLINE).collect(Collectors.joining( ", " ));
				
				
			} else {
			
				final List<String> internalClassNamesFinal = internalClassNames;
				potentialExternalXrefsForPreComment = externalClassNames.stream().limit(MAX_POTENTIAL_EXTERNAL_XREFS_INLINE)
																		.filter(er -> !internalClassNamesFinal.contains(er))
																		.collect(Collectors.joining( ", " ));
				
			}
			
			if(externalClassNames.size() > MAX_POTENTIAL_EXTERNAL_XREFS_INLINE)
				potentialExternalXrefsForPreComment = potentialExternalXrefsForPreComment + ", ...";
			
		}
		
		// Adding internal references PRE comment
		if(potentialInternalXrefsForPreComment != null && potentialInternalXrefsForPreComment.length() > 0) {
			
			//public void addPreCommentToInstruction(String comment, String prefixToCheck, Address addressInstruction) {
			String prefixComment = "Potential internal classes (FOX, max ";
			String potentialClasses = prefixComment + MAX_POTENTIAL_INTERNAL_XREFS_INLINE + "): " + potentialInternalXrefsForPreComment;
			
			if(DEBUG_LEVEL >= 1)
				printf("*** DEBUG 1 Adding potential internal classes as pre comment to function %s at address %s, limit %d: %s\n", methodName, addressInstruction.toString(),MAX_POTENTIAL_INTERNAL_XREFS_INLINE,potentialClasses);
			
			addPreCommentToInstruction(potentialClasses, prefixComment, addressInstruction, true);
			
		}
		
		// Adding external references PRE comment
		if(potentialExternalXrefsForPreComment != null && potentialExternalXrefsForPreComment.length() > 0) {
			
			String prefixComment = "Potential external classes (FOX, max ";
			String potentialClasses = prefixComment + MAX_POTENTIAL_EXTERNAL_XREFS_INLINE + "): " + potentialExternalXrefsForPreComment;
			
			if(DEBUG_LEVEL >= 1)
				printf("*** DEBUG 1 Adding potential external classes as pre comment to function %s at address %s, limit %d: %s\n", methodName, addressInstruction.toString(),MAX_POTENTIAL_EXTERNAL_XREFS_INLINE,potentialClasses);
			
			addPreCommentToInstruction(potentialClasses, prefixComment, addressInstruction, true);
						
		}
				
	}
	
	
	// Add a pre-comment to an instruction, checking if it is already present
	public void addPreCommentToInstruction(String comment, String prefixToCheck, Address addressInstruction, boolean replaceIfAlreadyPresent) {
		
		Instruction instruction = getInstructionAt(addressInstruction);
		
		String cur = instruction.getComment(CodeUnit.PRE_COMMENT);
		
		if (cur == null) {
			
			instruction.setComment(CodeUnit.PRE_COMMENT, comment);
			
		} else {
		
			// append tag to plate comment if not present already
			String comments[] = instruction.getCommentAsArray(CodeUnit.PRE_COMMENT);
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
					instruction.setCommentAsArray(CodeUnit.PRE_COMMENT, comments);
				
			} else {
				instruction.setComment(CodeUnit.PRE_COMMENT, cur + "\n" + comment);
			}
			
		}
		
		
	}
	
	// Add a pre-comment to an instruction
	public void addPreComment(Address addressInstruction, String className, String methodName, Address addressFunction) {
		
		if(DEBUG_LEVEL >= 1)
			printf("*** DEBUG 1 Adding pre comment to function %s of class %s at address %s\n", methodName, (className != null ? className : "null"), addressInstruction.toString());		
		
		String tag;
		
		if(className == null)			
			tag = "Called method name: " + methodName + ", missing information on the class";
		else if(addressFunction == null)
			tag = "Called method: " + className + " -> " +  methodName + ", external to the current binary";			
		else
			tag = "Called method: " + className + " -> " +  methodName + ", address " + addressFunction.toString();
			
		addPreCommentToInstruction(tag, tag, addressInstruction, false);
				
	}
	
	// DEBUG function: prints the maps and lists used by the plugin to files
	public void printListsToFile(String pathFolder) {
						
		printf("*** Printing msgSendFuncs to file");
		
		try {
		
			FileWriter fileWriter = new FileWriter(pathFolder + "msgSendFuncs");
			PrintWriter printWriter = new PrintWriter(fileWriter);
			
			for(int i=0; i< msgSendFuncs.size(); i++) {
				
				printWriter.write(msgSendFuncs.get(i).getName() + "\n");
								
			}
			
			printWriter.close();
			
		} catch(Exception e) {
			
			printf("*** EXCEPTION with msgSendFuncs to file");
			
		}
		
		// Map<String,List<MsgSendInvocationData>> msgSendInvocationsHashMap;
		printf("*** Printing msgSendInvocationsHashMap to file");
		
		try {
		
			FileWriter fileWriter = new FileWriter(pathFolder + "msgSendInvocationsHashMap");
			PrintWriter printWriter = new PrintWriter(fileWriter);
			
			for (Map.Entry<String, List<MsgSendInvocationData>> entry : msgSendInvocationsHashMap.entrySet()) {
				
				String currentKey = entry.getKey();		
				List<MsgSendInvocationData> currentList = entry.getValue();
				
				printWriter.write(currentKey + "\n");
				
				for(int i=0;i < currentList.size(); i++) {
					
					printWriter.write("\t" + currentList.get(i).getClassName() + " - " + currentList.get(i).getFunctionName() + "\n");
					
				}				
								
			}
			
			printWriter.close();
			
		} catch(Exception e) {
			
			printf("*** EXCEPTION with msgSendInvocationsHashMap to file");
			
		}
		
		printf("*** Printing functionsOfTheBinary to file");
		
		try {
		
			FileWriter fileWriter = new FileWriter(pathFolder + "functionsOfTheBinary");
			PrintWriter printWriter = new PrintWriter(fileWriter);
			
			for (Map.Entry<String, List<MsgSendInvocationData>> entry : functionsOfTheBinary.entrySet()) {
				
				String currentKey = entry.getKey();		
				List<MsgSendInvocationData> currentList = entry.getValue();
				
				printWriter.write(currentKey + "\n");
				
				for(int i=0;i < currentList.size(); i++) {
					
					printWriter.write("\t" + currentList.get(i).getClassName() + " - " + currentList.get(i).getFunctionName() + "\n");
					
				}				
								
			}
			
			printWriter.close();
			
		} catch(Exception e) {
			
			printf("*** EXCEPTION with functionsOfTheBinary to file");
			
		}
		
		//Map<String, List<String>> fridaExternalList;
		printf("*** Printing fridaExternalList to file");
		
		try {
		
			FileWriter fileWriter = new FileWriter(pathFolder + "fridaExternalList");
			PrintWriter printWriter = new PrintWriter(fileWriter);
			
			for (Map.Entry<String, List<String>> entry : fridaExternalList.entrySet()) {
				
				String currentKey = entry.getKey();		
				List<String> currentList = entry.getValue();
				
				printWriter.write(currentKey + "\n");
				
				for(int i=0;i < currentList.size(); i++) {
					
					printWriter.write("\t" + currentList.get(i) + "\n");
					
				}				
								
			}
			
			printWriter.close();
			
		} catch(Exception e) {
			
			printf("*** EXCEPTION with fridaExternalList to file");
			
		}
		
		printf("*** Printing functionsCallingMsgSend to file");
		
		try {
		
			FileWriter fileWriter = new FileWriter(pathFolder + "functionsCallingMsgSend");
			PrintWriter printWriter = new PrintWriter(fileWriter);
			
			for(int i=0; i< functionsCallingMsgSend.size(); i++) {
				
				printWriter.write(functionsCallingMsgSend.get(i).getName() + "\n");
								
			}
			
			printWriter.close();
			
		} catch(Exception e) {
			
			printf("*** EXCEPTION with functionsCallingMsgSend to file");
			
		}
		
	}
	
	
	// Support internal class
	private class MsgSendInvocationData {
		
		String functionName;
		Address address;
		String className;
						
		public MsgSendInvocationData(String functionName, Address address, String className) {
		
			this.functionName = functionName;
			this.address = address;
			this.className = className;
			
		}
		
		public String getFunctionName() {
			return functionName;
		}
		public void setFunctionName(String functionName) {
			this.functionName = functionName;
		}
		public Address getAddress() {
			return address;
		}
		public void setAddress(Address address) {
			this.address = address;
		}
		public String getClassName() {
			return className;
		}
		public void setClassName(String className) {
			this.className = className;
		}
				
		
	}
	
	
} 