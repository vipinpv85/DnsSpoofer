# LIBRARY without install
 - cd [parent folder]
 - meson build
 - ninja -C build


# LIBRARY with install
 - cd [parent folder]
 - meson build
 - ninja -C build install
 - ldconfig


## check the library

### without install:
 - PKG_CONFIG_PATH=[parent folder]build/meson-private/ pkg-config --cflags --libs libDnsSpoofer

### with install:
 - pkg-config --libs --cflags libDnsSpoofer

# Application

