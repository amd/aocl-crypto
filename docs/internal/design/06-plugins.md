# Plugin System design

Plugins are modules (refer to [Modules](#module-manager) for more information)
but externally loaded to support additional functionality.
Crypto framework does not differentiate between plugins and already existing
modules. The application software should make additional configuration to
request new algorithm.

Each plugin uses different API's to get themselves registered. This is to
differentiate between existing algorithms and dynamically loaded ones.

There are two ways to configure a plugin
  1. By setting environment variable `ALCP_PLUGINS` as a comma separated value.
     The plugin initialization happens from the library at initialization time.
  2. By using `LD_PRELOAD` in which case the active initialization happens from
     the plugin. OR by making the library as a link time option for application.


We take the (2) as the approach as it is more portable over (1).

Each plugin will have its own `alcp_plugin_info_t` structure

```c

typedef
struct  alc_plugin_info {
    const char *name;
} alc_plugin_info_t;


typedef
struct alc_plugin_ops {
    
} alc_plugin_ops_t;

```

## Plugin APIs

This section describes the API design for 'C', the same can be used by many
other languages using their respective FFI(Foreign Function Interface).

Plugins are loaded in two ways : 
  1. By using the `ALCP_PLUGINS` environment variable, which can be parsed on
     Linux/Windows environment for a given application in its own context.
  2. Programatically using the plugin APIs.

The environment variable `ALCP_PLUGINS` is a comma or semi-colon separated list
of plugin names. The AOCL Crypto library will load the plugins and initialize.

Plugins are identified using their filename; for example: an file name which has
prefix `alcp-plugin-aead` (and filename as `alcp-plugin-aead.so` or
`alcp-plugin-dev-msm.so`)should use the plugin name as `"aead".

Given multiple plugins `ALCP_PLUGINS` can be used as follows
```sh
$ export ALCP_PLUGINS="aead,dev-msm"

```


Plugins can be loaded using API `alcp_plugin_load()`
```c
alc_error_t
alcp_plugin_load(const char *name);
```
If the plugin is not available error can be checked as usual.
```c
if (alc_is_error(ret)) {
    // Take action
}
```

After load it is recommended that the plugin is initialized for any necessary
actions that needs to be performed. Usually the loader program will call
`plugin_init()` after successful load. The `plugin_info_t` will be part of the
plugin which identifies the plugin and provides a callback to initialize.


Unloading of plugin can be performed using `alcp_plugin_unload`, if the plugin
is not available, the request is simply ignored than reporting error.

```c
void
alcp_plugin_unload(const char *name);
```


# Plugin for Device off-loading

Offloading support is an additional feature that needs to be supported in order
to extend the APIs. All the loaded device-plugins are searched for successful
initialization. They are searched in the order loaded, assuming that only one of
them will ever succeed on a platform.

All the others will return error codes via the `alc_error_t` type; and can be
checked using `alcp_is_error()` call.

Device plugins have slightly different API naming compared to other plugins to
enable the device management.

For more information please refer to the section describing off-loading support
in [Device Offloading](#device-offloading)
