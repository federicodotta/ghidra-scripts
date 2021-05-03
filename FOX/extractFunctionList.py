import frida
import sys
import signal

# Device selection (network/usb)
#device = frida.get_usb_device()
device = frida.get_remote_device()

# Program identifier
program_identifier = "com.apple.weather"

# spawn or just attach?
program_spawn = True

# True to output the list to a local file in the device storage, false to output directly to the storage of the client
# Output to the device local storage is more reliable, specially with big binaries
outputToDeviceFile = True

# With outputToDeviceFile to True is the file name on the device storage (the relative path will be get by Frida runtime), otherwise is the full path on the client storage
#outputPath = "C:\\Users\\Test\\FOX\\methodsList.txt"
outputPath = "methodsList.txt"


if not outputToDeviceFile:
    # client output file
    f = open(outputPath, 'w')  


def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    if program_spawn == True:
        device.kill(pid)
    sys.exit(0)

def on_message(message, data):

    if not outputToDeviceFile:
        f.write(message['payload'] + '\n')
    else:
        print(message['payload'])


if program_spawn == True:
    try:
        pid = device.spawn([program_identifier])
    except Exception as e:
        print("ERROR")
        print(e)
        sys.exit(0)

    print("Process created: " + program_identifier)
    print("Current pid: " + str(pid))

    session = None

    print("Waiting for device...")

    session = None

    # Attach to device
    while session is None:
        try:
            if program_spawn == True:
                session = device.attach(pid)
            else:
                session =  device.attach(program_identifier)
        except Exception as e:
            print("ERROR")
            print(e)
            pass

        print("Attached to: " + program_identifier)

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

if outputToDeviceFile:
    content = content.replace("XXXXX","true")
    content = content.replace("YYYYY",outputPath)
else:
    content = content.replace("XXXXX","false")

# inject frida JS
script = session.create_script(content)

script.on('message', on_message)

script.load()

# Intercept Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

device.resume(pid)

rpc = script.exports

rpc.dumpmetods();

if not outputToDeviceFile:
    print("Dump done!");
    print("File list has been saved in " + outputPath)

sys.stdin.read()

print("EXITED")
