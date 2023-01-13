project('SNIpRoxy', 'c', license: 'AGPL-3.0-or-later', version: '0.1.0')
dependencies = [ dependency('gnutls'), dependency('c-ares', modules: ['c-ares::cares']), dependency('baSe') ]
executable(
    'snir',
    'main.c', 'inbound.c', 'outbound.c', 'server.c', 'connection.c', 'dns_cache.c', 'keypair.c', 'ca.c',
    'thread_common.c',
    dependencies: dependencies, gnu_symbol_visibility: 'hidden'
)
dns_cache_test = executable(
    'dns-cache-test',
    'dns_cache.test.c', 'dns_cache.c',
    dependencies: dependencies, gnu_symbol_visibility: 'hidden'
)
test('dns cache', dns_cache_test)