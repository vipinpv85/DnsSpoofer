cc = meson.get_compiler('c')

#dnsSpoofer_linkargs = ['/usr/local/lib/x86_64-linux-gnu/libDnsSpoofer.so', ]
#add_project_link_arguments(dnsSpoofer_linkargs, language: 'c')

test_dns = executable('test_StCreateDevice', 'test1.c', dependencies: [], )
test('invalidParam', test_dns, args : ['portCheck', 'NULL', '12'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['portCheck', 'NULL', '-2'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['portCheck', '123455', '6'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['portCheck', '-1234', '6'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['portCheck', '12saq12321321as', '10'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['ChangeFromDnsName', 'NULL', '0'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['ChangeFromDnsName', 'NULL', '1'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['ChangeFromDnsName', '3w4doo3c', 'valid'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['ChangeFromDnsName', '3w4doo3c', 'invalid'], is_parallel : true, priority : 0, suite: 'invalid')

test('validParam', test_dns, args : ['1234', '4'], is_parallel : true, priority : 0, suite: 'valid')
test('validParam', test_dns, args : ['3www5google3com', 'valid'], is_parallel : true, priority : 0, suite: 'valid')

message('To run all tests               : meson test')
message('To run tests with error log	: meson test --print-errorlogs')
message('To run all invalid tests       : meson test -C build --suite invalid')
message('To run all valid tests         : meson test -C build --suite valid')

