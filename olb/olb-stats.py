#!/usr/bin/env python

import netsnmp
import os
import time
from pyrrd.rrd import DataSource, RRA, RRD

sysfetch = {}
sysfetch['cpu'] = {}
sysfetch['cpu']['oid'] = {}
sysfetch['cpu']['ds'] = {}
sysfetch['cpu']['oid']['user']        = '.1.3.6.1.4.1.2021.11.9.0'
sysfetch['cpu']['oid']['system']      = '.1.3.6.1.4.1.2021.11.10.0'
sysfetch['cpu']['oid']['idle']        = '.1.3.6.1.4.1.2021.11.11.0'
sysfetch['cpu']['ds']['user']         = 'GAUGE'
sysfetch['cpu']['ds']['system']       = 'GAUGE'
sysfetch['cpu']['ds']['idle']         = 'GAUGE'

sysfetch['memory'] = {}
sysfetch['memory']['oid'] = {}
sysfetch['memory']['ds'] = {}
sysfetch['memory']['oid']['total']    = '.1.3.6.1.4.1.2021.4.6.0'
sysfetch['memory']['oid']['free']     = '.1.3.6.1.4.1.2021.4.11.0'
sysfetch['memory']['oid']['shared']   = '.1.3.6.1.4.1.2021.4.13.0'
sysfetch['memory']['oid']['buffered'] = '.1.3.6.1.4.1.2021.4.14.0'
sysfetch['memory']['oid']['cached']   = '.1.3.6.1.4.1.2021.4.15.0'
sysfetch['memory']['ds']['total']     = 'GAUGE'
sysfetch['memory']['ds']['free']      = 'GAUGE'
sysfetch['memory']['ds']['shared']    = 'GAUGE'
sysfetch['memory']['ds']['buffered']  = 'GAUGE'
sysfetch['memory']['ds']['cached']    = 'GAUGE'

sysfetch['swap'] = {}
sysfetch['swap']['oid'] = {}
sysfetch['swap']['ds'] = {}
sysfetch['swap']['oid']['total']      = '.1.3.6.1.4.1.2021.4.3.0'
sysfetch['swap']['oid']['free']       = '.1.3.6.1.4.1.2021.4.4.0'
sysfetch['swap']['ds']['total']       = 'GAUGE'
sysfetch['swap']['ds']['free']        = 'GAUGE'

sysfetch['ifaces'] = {}
sysfetch['ifaces']['oid'] = {}
sysfetch['ifaces']['ds'] = {}
sysfetch['ifaces']['oid']['ilist']    = '.1.3.6.1.2.1.2.2.1.2'
sysfetch['ifaces']['oid']['oin']      = '.1.3.6.1.2.1.31.1.1.1.6'
sysfetch['ifaces']['oid']['oout']     = '.1.3.6.1.2.1.31.1.1.1.10'

RRDDIR = "rrd"

now = str(int(time.time()))

def create_rrd(filename, args):
    dses = []
    rras = []

    for ds in args['ds']:
        dses.append(
        DataSource( dsName=ds, dsType=args['ds'][ds], heartbeat=600))
    
    rras.append(RRA(cf='AVERAGE', xff=0.5, steps=1, rows=288))
    rras.append(RRA(cf='AVERAGE', xff=0.5, steps=12, rows=744))
    rras.append(RRA(cf='AVERAGE', xff=0.5, steps=24, rows=1116))
    rras.append(RRA(cf='AVERAGE', xff=0.5, steps=48, rows=2191))
    myRRD = RRD(
        filename, ds=dses, rra=rras, start=int(now)-60)
    myRRD.create()

for stype in sysfetch:
    rrd = ""
    values = []
    values.append(now)
    if stype in [ 'cpu', 'memory', 'swap' ]:
        rrd = os.path.join(RRDDIR, stype+'.rrd')
        if os.path.isfile(rrd) == False:
            create_rrd(rrd, sysfetch[stype])
            print "Create %s" % (rrd)

        myRRD = RRD(rrd)
        for s in sysfetch[stype]['oid']:
            r = netsnmp.snmpget(sysfetch[stype]['oid'][s], Version=2, DestHost='localhost', Community='public')
            values.append(str(r[0]))

        myRRD.bufferValue(':'.join(values))
        myRRD.update()

#filename = '/tmp/test.rrd'
#
#if os.path.isfile(filename) == False:
#    dataSources = []
#    roundRobinArchives = []
#    dataSources.append(
#        DataSource( dsName='user', dsType='GAUGE', heartbeat=600))
#    dataSources.append(
#        DataSource( dsName='system', dsType='GAUGE', heartbeat=600))
#    dataSources.append(
#        DataSource( dsName='idle', dsType='GAUGE', heartbeat=600))
#    
#    roundRobinArchives.append(RRA(cf='AVERAGE', xff=0.5, steps=1, rows=288))
#    roundRobinArchives.append(RRA(cf='AVERAGE', xff=0.5, steps=12, rows=744))
#    roundRobinArchives.append(RRA(cf='AVERAGE', xff=0.5, steps=24, rows=1116))
#    roundRobinArchives.append(RRA(cf='AVERAGE', xff=0.5, steps=48, rows=2191))
#    myRRD = RRD(
#        filename, ds=dataSources, rra=roundRobinArchives, start=int(now)-60)
#    myRRD.create()
#else:
#    myRRD = RRD(filename)
#
#r = []
#r.append(now)
#
#myRRD.bufferValue(':'.join(r))
#myRRD.update()
#
##
##  515  snmpwalk -v2c -c public localhost .1.3.6.1.4.1.2021.11.9.0
##    516  snmpwalk -v2c -c public localhost .1.3.6.1.4.1.2021.11.10.0
##      517  snmpwalk -v2c -c public localhost .1.3.6.1.4.1.2021.11.11.0
##
#
##         RRA:AVERAGE:0.5:1:288 \
##         RRA:AVERAGE:0.5:12:31
##                         24:93
##                         48:183
#
