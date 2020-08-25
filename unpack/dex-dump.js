'use strict'
/*
* Use JS code read android devices memory.
* Only supported versions 4 ~ high level
* Android 4: hook dvmDexFileOpenPartial
* Android 5: hook OpenMemory
* After Android 5: hook OpenCommon
* Test environment | android version: 7
* Run dex-dump: $ frida -U -f <packageName> -l dex-dump.js --no-pause
*/

const processName = '<packageName>'

function getAndroidVersion(){
    var version = 0;
    if(Java.available){
        var versionStr = Java.androidVersion;
        version = versionStr.slice(0,1);
    }else{
        console.log('[*] Error: cannot get android version');
    }
    console.log('[*]Android Version: ' + version);
    return version;
}

function getFunctionPointer(version){
    var functionPointer = undefined;
    if (version > 4){  // android version 5 and later.
        functionPointer = findMemoryWriterExport(functionPointer, 'OpenMemory', 'libart.so');
        if (functionPointer === undefined){
            functionPointer = findMemoryWriterExport(functionPointer, 'OpenCommon', 'libart.so');
        }
    }else if (version === 4){  // android 4 different 5 or later.
        functionPointer = findMemoryWriterExport(functionPointer, 'dexFileParse', 'libdvm.so');
        if (functionPointer === undefined){
            functionPointer = findMemoryWriterExport(functionPointer, 'OpenMemory', 'libart.so');
        }
    }
    return functionPointer;
}

function findMemoryWriterExport(functionPtr, exportFunctionIndex, hexFileName){
     var artExports =  Module.enumerateExportsSync(hexFileName);
     for (var i = 0; i < artExports.length; i++){
        if (artExports[i].name.indexOf(exportFunctionIndex) !== -1){
            var functionName = artExports[i].name;
            functionPtr = Module.findExportByName(hexFileName, artExports[i].name);
            break;
        }
     }
     return functionPtr;
}

function checkDex(dataPointer, dexHex){
    // match flag. if match return true.
    var dexMatch = true;
    for(var i = 0; i < 8; i++){
        if(Memory.readU8(ptr(dataPointer).add(i)) !== dexHex[i]){
            dexMatch = false;
            break;
        }
    }
    return dexMatch;
}

function checkUsualDex(dataPointer){
    const dexHex = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00];
    var dexMatch = checkDex(dataPointer, dexHex);
    return dexMatch;
}

function checkODex(dataPointer){
    const dexHex = [0x64, 0x65, 0x79, 0x0a, 0x30, 0x33, 0x36, 0x00];
    var dexMatch = checkDex(dataPointer, dexHex);
    return dexMatch;
}

function dexDump(functionPtr){
        Interceptor.attach(functionPtr,{
            onEnter: function(args){
                var begin = 0;
                var dexMatch = false;
                var oDexMatch = false;
                for (var i = 0; i < 2; i++){
                    dexMatch = checkUsualDex(args[i]);
                    if(dexMatch === true){
                        begin = args[i];
                    }else{
                        oDexMatch = checkODex(args[i]);
                        if(oDexMatch === true){
                            begin = args[i];
                        }
                    }
                    if (begin !== 0){
                        break;
                    }
                }
                if(dexMatch === true){
                    console.log('[*] Find flag string: ', Memory.readUtf8String(begin));
                    var address = parseInt(begin,16) + 0x20;
                    var DexSize = Memory.readInt(ptr(address));
                    console.log('[*] DexSize :', DexSize);
                    var dexPath = '/data/data/' + processName + '/' + DexSize + '.dex';
                    var DexFile = new File(dexPath, "wb");
                    DexFile.write(Memory.readByteArray(begin, DexSize));
                    DexFile.flush();
                    DexFile.close();
                    console.log("[*] dump Dex success, saved path: ", dexPath);
                }else if(oDexMatch === true){
                    console.log("[*] Find flag string: ", Memory.readUtf8String(begin));
                    var address = parseInt(begin,16) + 0x0C;
                    var ODexSize = Memory.readInt(ptr(address));
                    console.log("[*] ODexSize :", ODexSize);
                    var ODexPath = "[*] /data/data/" + processName + "/" + ODexSize + ".odex";
                    var ODexFile = new File(ODexPath, "wb");
                    ODexFile.write(Memory.readByteArray(begin, ODexSize));
                    ODexFile.flush();
                    ODexFile.close();
                    console.log("[*] dump ODex success, saved path: " + ODexPath + "\n");
                }
            },
            onLeave: function(retval){
            }
        });
}

//start dump dex file
var androidVersion = getAndroidVersion();
var functionPtr = getFunctionPointer(androidVersion);
if(functionPtr !== undefined){
    dexDump(functionPtr);
}else{
    console.log('[*] Match Error.')
}
