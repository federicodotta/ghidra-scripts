#!/usr/bin/env python
import frida
import sys

# Frida Python docs: https://github.com/frida/frida-python/blob/main/frida/core.py#L821

# Device selection
device = frida.get_local_device()

# Program name
program_identifier = "Desktop Postflop"

outputPath = "methodsList.txt"


def on_message(message, data):
    print(message['payload'])


session = device.attach(program_identifier)


print("Attached to: " + program_identifier)
print("PID: " + str(session))
print(dir(session))

print("Waiting for device...")

print("Injecting code... ")

content = """
var dumpToLocalFile = XXXXX;  
var outputPath = 'YYYYY';

// enumerate all ObjC classes
function enumAllClasses() {
    var allClasses = [];

    for (var aClass in ObjC.classes) {
        if (ObjC.classes.hasOwnProperty(aClass)) {
            allClasses.push(aClass);
        }
    }
    return allClasses;
}

// enumerate all methods declared in an ObjC class
function enumMethods(targetClass) {
    var ownMethods = ObjC.classes[targetClass].$ownMethods;
    return ownMethods;
}

// enumerate all methods declared in all ObjC classes
function enumAllMethods() {
    var allClasses = enumAllClasses();
    var allMethods = {}; 

    var outputFile;
    if(dumpToLocalFile) {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        outputPath = NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString() + "/Documents/" + outputPath;

        send("Output path: " + outputPath)

        outputFile = new File(outputPath,'w');
    }
    allClasses.forEach(function(aClass) {
        if(dumpToLocalFile) {
            outputFile.write(aClass); 
            outputFile.write('\\n');
        } else {
            send(aClass);
        }

        enumMethods(aClass).forEach(function(method) {
            if(dumpToLocalFile) {
                outputFile.write(method);
                outputFile.write('\\n');
            } else {
                send(method);
            }
        });
    });

    if(dumpToLocalFile) {
        outputFile.flush();
        outputFile.close();

        send("Dump done!");
        send("File list has been saved in the device at " + outputPath)
    }
}

rpc.exports = {
    dumpmetods: function() {
        enumAllMethods();
    }
};
"""

content = content.replace("XXXXX", "true")
content = content.replace("YYYYY", outputPath)

# inject frida JS
script = session.create_script(content)

script.on('message', on_message)

script.load()

session.resume()

rpc = script.exports

rpc.dumpmetods();
