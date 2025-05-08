# Dynamic Loading Feature
Dynamic loading of library is a necessary feature to support allow extensible
library. Here the extension is for supporting new devices that may arrive in
near future, but library itself doesn't have to have support for immediate use.

## Dynamic library loading
Libraries are built as part of the "Provider Kit", herein referred to as PK. The
PK provides features / functionalities that are not already part of the library.
Also it helps reduce the size of the linked library where the specific module,
device is not present or not needed.

Libraries are provided both as static library and as dynamic loadable. This
section just presents the dynamic loading part. 

The cases where libraries are provided as static or archived versions (like as
in .a or .lib), the library just needs to be linked at the final stage of
compilation.

Static libraries usually hosts a 'constructor' functions which gets called at
the very beginning of the program execution. The extended module registers
itself as part of the library.

## Dynamic Feature/Class loading
Once the library is loaded, one way or another.


## Design
Since each operating systems implements dynamic loading differently, there is a
wrapper class present in __dynlib.cc_. the implementation details are present in
_impl/dynlib\_linux.cc_ for Linux or Unix specific loading which makes use of
the _libdl.so_ APIs _dlopen()_, _dlclose()_ and _dlsym()_ etc.

Windows specific implementation should be present in _impl/dynlib\_win.c_

### DynamicLibrary class

`DynamicLibrary` class supports following functionality:
 - `load()` - loads a library
 - `unload()` - unload a previously loaded library
 - `isLoaded()` - checks if the loading was successful
 - `getSymbol()` - get a symbol that is part of the symbol table.
 - `suffix()` - gets the library suffix for a given operating system.
 - `setSearchPath()` - Sets the search path for loading libraries, usually its
   just current directory
 
### ClassLoader class
This class implements loading a class, but for now this portion is not
implemented as the final decision on whether to allow C interface or C++
interface for the
 
