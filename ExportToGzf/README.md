# ExportToGzf

ExportToGzf is a simple Ghidra script that can be used to export a Ghidra project in gzf format. An exported project can be then imported by creating a new Ghidra project and selecting the "Import file..." option. The plugin can be used in GUI and in headless mode, but it is more useful in this last mode because at the current version of Ghidra it is not possible to export a project.

Based on beigela python script posted [here](https://github.com/NationalSecurityAgency/ghidra/issues/2104).

Tested with Ghidra v9.2.3.

## Usage

### Headless mode

1.	Launch analyzeHeadless with -postScript ExportToGzf.java #OUTPUT_PATH
2.	If #OUTPUT_PATH parameter is not supplied, the gzf is saved in the ghidraProject.gzf file of current directory
 
### GUI mode

1.	Copy the script into your ghidra_scripts directory
2.	Open the Script Manager in Ghidra and run the script
3.	You can also run it via the Tools > ExportToGzf menu or the shurtcut "E"

## Author
- Federico Dotta -  Principal Security Analyst at HN Security
