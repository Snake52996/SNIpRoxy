project('SNIpRoxy', 'c', license: 'AGPL-3.0-or-later', version: '0.1.0')
dependencies = [ dependency('gnutls'), dependency('c-ares', modules: ['c-ares::cares']), dependency('baSe') ]
executable('snir', 'main.c', 'inbound.c', 'outbound.c', 'server.c', 'connection.c', 'dns_cache.c', 'keypair.c', 'ca.c', dependencies: dependencies)