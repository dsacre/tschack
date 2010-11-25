#! /usr/bin/env python
# encoding: utf-8

# look for 'meow' below
import Options

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

def configure(conf):
    conf.check_tool('compiler_cxx')
    conf.check_tool('compiler_cc')
    conf.env.CXXFLAGS = [ '-O3', '-g']
    conf.sub_config('drivers')

def build(bld):
    bld.add_subdirs('jackd')
    bld.add_subdirs('libjack')
    bld.add_subdirs('drivers')

