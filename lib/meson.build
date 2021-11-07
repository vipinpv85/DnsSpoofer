cc = meson.get_compiler('c')

lib_c_args = []
link_c_args = []
sources = ''

thread_dep = dependency('threads', required : true)

include_dir += include_directories('include')
subdir('src')

self_lib += shared_library(
	meson.project_name(),
	sources,
        c_args : lib_c_args,
        link_args: link_c_args,
        include_directories : [include_dir, ],
        dependencies: [thread_dep],
        install: true)
