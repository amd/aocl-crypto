# Preloading

When you specify LD_PRELOAD=/path/to/somelib.so, loader will load this library first before loading the actual program into memory. This dynamic linking in any program which is running with preloaded library will try to find the symbol in preloaded library first before attempting to search LD_LIBRARY_PATH for the library specified in the ELF executable. This means even though another lib which may have same symbol is available, preloaded library overrides the linkage during run time.

To read more about preloading, please check [ld.so man page](https://man7.org/linux/man-pages/man8/ld.so.8.html) and [ld man page](https://linux.die.net/man/1/ld).

## Temporary Preloading

To preload temporarily, one can modify the environment variable LD_PRELOAD. This can be setup in bashrc or zshrc or any rc file of your shell leading to semi permanent preloading. Even if we can setup the same concept  in /etc/environment, for a more permanent setup, LD_PRELOAD is not recommended.

LD_PRELOAD can be used for on demand preloading to test out if preloading works as indented. Temporary preloading is also recommended because it does not modify the loader parameters for programs that do not require the preload.

If you are looking for a more perminant setup which is not recommended, you can look below.

## Permanent Preloading

<font color="red">Warning: This type of preloading may break some other program which may load symbols with same name and parameter list as the preloaded library. Only use this if you know what you are doing and is really sure that there would be no such conflicts.</font>

To preload permanently, you would need to either set LD_PRELOAD environment globally as discussed above but its not the way it is supposed to be done.

In order to preload globally there is a config file `/etc/ld.so.preload` this file by default do not exist in any machine as its not a good idea to preload library globally. You can create/edit this file and add path of each `.so` file you wish to preload line by line.

Example /etc/ld.so.preload

```bash
/path/to/somelib.so
/path/to/someotherlib.so
```

Lines are parsed in order that means `somelib.so` will override all the symbols exported by `someotherlib.so`. 

## Precedence of Loading

Precedence of loading is determined by is it preloaded, does the lib come first in the list.

Let's say for example you are preloading `lib1.so lib2.so` while loading `lib3.so lib4.so` because inside elf its specified to load it.

`LD_LIBRARY_PATH=/some/path/lib1.so:/some/path/lib2.so ./someexecutable`

If some executable is linked to lib3.so and lib4.so in order. Then the symbol lookup order will be

1) `lib1.so`
2) `lib2.so`
3) `lib3.so`
4) `lib4.so`

You can say that `lib1.so` and `lib2.so` will override both `lib3.so` and `lib4.so` as they are preloaded. lib1.so will override `lib2.so` as its the first in the list. `lib3.so` will override `lib4.so` as `lib3.so` comes first.

## Editing linkage

In Linux you can edit the linkage of an executable,  this can be used to remove the linkage to existing library to replace with a better version of it or some other library which exports the same symbols and does the same thing as the other library but better.

Editing linkage is not recommended if the program has multiple executables, as every executable's linkage needs to be edited.

In order to edit the linkage of a program or library, you need to install a package known as `patchelf`. 

### Important Arguments of patchelf

1. `--remove-needed` - removed a lib as needed, thereby loader does not load it anymore.
2. `--add-needed` - add a lib as needed, loader loads if any symbols are there in this which can be linked during run time then it will link it.
3. `--replace-needed` - replaces already needed lib with a new lib, this can be seen as a combination of above two arguments.

To know more about the parameters do

```bash
patchelf --help
```

or [click here](https://man.archlinux.org/man/community/patchelf/patchelf.1.en)

[Preloading_IPP]:

## Preloading IPP-CP wrapper plugin.

Assuming that you are in the package root directory and you have IPPCP setup and in the environment.

```bash
LD_PRELOAD=$PWD/lib/libipp-compat.so executable_path
```

Example with Intel IPP AES CTR Encryption.

```bash
wget https://raw.githubusercontent.com/intel/ipp-crypto/ipp-crypto_2021_6/examples/aes/aes-256-ctr-encryption.cpp -O aes-256-ctr-encryption.cpp
g++ aes-256-ctr-encryption.cpp -o aes-ctr -lippcp
LD_PRELOAD=$PWD/lib/libipp-compat.so ./aes_ctr
```

