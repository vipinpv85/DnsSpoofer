project('DnsSpoofer', 'c', default_options: ['c_std=gnu11', 'buildtype=release'], version: '1.0',)

add_global_arguments('-DBUILD="' + meson.project_version() + '"', language : 'c')

self_lib = []
include_dir = []
public_include_dir = 'include/'
include_dir += include_directories('include')

#install header files
subdir('include')

#build library
subdir('lib')

pkg = import('pkgconfig')
pkg.generate(
                name : meson.project_name(),
                version : meson.project_version(),
                libraries : self_lib,
                filebase : 'lib' + meson.project_name(),
                description : 'DNS Spoofer library and example' )
