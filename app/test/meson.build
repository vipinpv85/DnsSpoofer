cc = meson.get_compiler('c')

#dnsSpoofer_linkargs = ['/usr/local/lib/x86_64-linux-gnu/libDnsSpoofer.so', ]
#add_project_link_arguments(dnsSpoofer_linkargs, language: 'c')

test_dns = executable('test_dns', 'test1.c', dependencies: [], )

# format of arguments - [success|failure, function, args ...] 
test('invalidParam', test_dns, args : ['0', 'portCheck', 'NULL', '12'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['0', 'portCheck', 'NULL', '-2'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['0', 'portCheck', '123455', '6'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['0', 'portCheck', '-1234', '6'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['0', 'portCheck', '12saq12321321as', '10'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['0', 'ChangeFromDnsName', 'NULL', 'valid'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['0', 'ChangeFromDnsName', 'NULL', 'invalid'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['0', 'ChangeFromDnsName', '3www4doo0', 'valid'], is_parallel : true, priority : 0, suite: 'invalid')
test('invalidParam', test_dns, args : ['0', 'ChangeFromDnsName', '3www4doo0', 'invalid'], is_parallel : true, priority : 0, suite: 'invalid')

test('validParam', test_dns, args : ['1', 'portCheck', '1234', '4'], is_parallel : true, priority : 0, suite: 'valid')
test('validParam', test_dns, args : ['1', 'ChangeFromDnsName', '3www6google3com0', 'valid'], is_parallel : true, priority : 0, suite: 'valid')

message('To run all tests               : meson test')
message('To run tests with error log	: meson test --print-errorlogs')
message('To run all invalid tests       : meson test -C build --suite invalid')
message('To run all valid tests         : meson test -C build --suite valid')

