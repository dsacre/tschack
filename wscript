#! /usr/bin/env python
# encoding: utf-8

# look for 'meow' below
import Options
import os

# the following two variables are used by the target "waf dist"
VERSION='0.0.1'
APPNAME='tschack'

# these variables are mandatory ('/' are converted automatically)
srcdir = '.'
blddir = 'build'

def set_options(opt):
    # options provided by the modules
    opt.tool_options('compiler_cxx')
    opt.tool_options('compiler_cc')

    opt.add_option('--libdir', type='string', help="Library directory [Default: <prefix>/lib]")

def configure(conf):
    conf.check_tool('compiler_cxx')
    conf.check_tool('compiler_cc')
    conf.env.CXXFLAGS = [ '-O3', '-g']

    if Options.options.libdir:
	conf.env['LIBDIR'] = Options.options.libdir
    else:
	conf.env['LIBDIR'] = os.path.join( conf.env['PREFIX'], 'lib' )

    conf.define( 'ADDON_DIR', os.path.join( conf.env['LIBDIR'], 'jack' ) )
    conf.define( 'JACK_LOCATION', os.path.join( conf.env['PREFIX'], 'bin' ) )
    conf.define( 'VERSION', VERSION )
    conf.define( 'DEFAULT_TMP_DIR', '/dev/shm' )
    conf.define( 'PROTOCOL_VERSION', '100' )
    conf.define( 'JACK_DEFAULT_DRIVER', 'alsa' )
    conf.define( 'JACK_THREAD_STACK_TOUCH', 500000 )
    conf.define( 'JACK_SEMAPHORE_KEY', 0x282929 )

    conf.define( 'JACK_SHM_TYPE', 'System V' )
    conf.define( 'HAVE_CLOCK_GETTIME', 1 )

    conf.sub_config('drivers')
    conf.sub_config('example-clients')
    conf.sub_config('tools')

    conf.write_config_header('config.h')

def build(bld):
    bld.add_subdirs('jackd')
    bld.add_subdirs('libjack')
    bld.add_subdirs('drivers')
    bld.add_subdirs('example-clients')
    bld.add_subdirs('tools')


