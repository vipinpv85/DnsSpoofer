project('DnsSpoofer Library Application', 'c',
                default_options: ['c_std=gnu11', 'buildtype=release'],
                version: '1.0',)

common_app_src = []
include_dir = []
lib_c_args = []
lib_link_args = []

if get_option('app') == 'posix'
	subdir('posix')
elif get_option('app') == 'dpdk'
	subdir('dpdk')
elif get_option('app') == 'ebpf'
	subdir('ebpf')
else
	error('Application mode is unknown, please use "posix|dpdk|ebpf" mode!')
endif

subdir('test')
