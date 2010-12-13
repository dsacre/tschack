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
    opt.tool_options('gnu_dirs')
    opt.tool_options('misc')

def configure(conf):
    conf.check_tool('compiler_cxx')
    conf.check_tool('compiler_cc')
    conf.check_tool('gnu_dirs')
    conf.check_tool('misc')

    conf.env.CXXFLAGS = [ '-O3', '-g']


    print conf.env['LIBDIR']
    conf.define( 'ADDON_DIR', os.path.join( conf.env['LIBDIR'], 'jack' ) )
    conf.define( 'JACK_LOCATION', conf.env['BINDIR'] )
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

    # create the jack.pc file for pkg-config
    jackpc = bld.new_task_gen('subst')
    jackpc.source = 'jack.pc.in'
    jackpc.target = 'jack.pc'
    jackpc.install_path = '${PREFIX}/lib/pkgconfig'

