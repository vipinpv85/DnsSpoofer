compiler = meson.get_compiler('c')

lib_c_args = []
link_c_args = []

dpdkcflags = run_command('pkg-config', '--cflags', 'libdpdk')
dpdklibs = run_command('pkg-config', '--static', '--libs', 'libdpdk')

if dpdkcflags.returncode() != 0
        error('Need cflags for DPDK!')
endif

if dpdklibs.returncode() != 0
        error('Need ldflags for DPDK!')
endif

link_c_args += [dpdklibs.stdout().strip().split()]
lib_c_args += [dpdkcflags.stdout().strip().split()]

lib_c_args += [ '-Werror', '-march=native', ]

sources = [ 'dnsSock.c', ]

dnsSpoofer_dep = dependency('threads', required : true)

#dnsSpoofer_cflags = run_command('pkg-config', '--static', '--cflags', 'libDnsSpoofer')
#if dnsSpoofer_cflags.returncode() != 0
#       error('failed to get DNS Spoofer libraries, please build and install!')
#endif
#lib_c_args += [dnsSpoofer_cflags.stdout().strip().split()]

dnsSpoofer_linkargs = ['/usr/local/lib/x86_64-linux-gnu/libDnsSpoofer.so', ]
add_project_link_arguments(dnsSpoofer_linkargs, language: 'c')


#build executable
executable(
		'dnsSpoofer',
		sources,
        	c_args : lib_c_args,
	        link_args: link_c_args,
		include_directories : include_dir,
		dependencies: [dnsSpoofer_dep],
		install: false)

