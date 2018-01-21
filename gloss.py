#!/usr/bin/env python
#
# gloss -- Grep for Logs on Open Source Systems
#
# Parse the lines in log files, and perform selections on them to
# bind variables, selecting on some and outputting others, to
# create queries and to present in an appetiting manner.
#
# A typical use would be a Postfix MTA, which logs many things about
# messages, with transaction identities and email addresses, that can
# be very useful when wrapped into clickable web pages.
#
# Drivers mention variables by name.  They are resolved in this order:
#  - within an explicit scope, when given
#  - within the current driver's scope
#  - within the surrounding log entry scope
# Variables of drivers are prefixed by the driver name; variables of
# gloss itself are not prefixed.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import time

import re
import argparse


#
# Commandline argument parser
#

argprs = argparse.ArgumentParser (prog="gloss",
		usage="Grep Logs on Open Source Systems -- helps to gloss over logs",
		description="Log files are long and detailed; this tool structures their contents and helps to relate matching identifier fields",
		add_help=False)

argprs.add_argument ('-f', '--logfile',
		default=None,
		action='append',
		help='explicit specification of a logfile to gloss over; may specify more than one; defaults are introduced by most --driver specifications; in absense of those, /var/log/syslog and /var/log/messages are used')

argprs.add_argument ('-l', '--log-facility',
		type=str,
		default='*.*',
		action='append',
		help='log f1cility; used to find references in syslog.conf')

argprs.add_argument ('-b', '--before',
		type=str,
		default=None,
		help='select events before this time; when out of order with --after, drop the range instead of requiring it; may be an integer timestamp, a date/time, or a time (ranging back 24h)')

argprs.add_argument ('-a', '--after',
		type=str,
		default=None,
		help='select events before this time; when out of order with --after, drop the range instead of requiring it; may be an integer timestamp, a date/time, or a time (ranging back 24h)')

argprs.add_argument ('-p', '--pid', '--proc',
		type=str,
		default=[],
		action='append',
		help='set a PID;maybe a path to a file holding a PID; may be a tcp:port or udp:port or sctp:port; may be a program name to match')

argprs.add_argument ('-h', '--hostname',
		type=str,
		default=None,
		action='append',
		help='for the logging host name, as represented in the log files; defaults to match all hosts; multiple hosts can be presented as explicit alternatives')

argprs.add_argument ('-d', '--driver',
		type=str,
		default=None,
		action='append',
		help='for a driver; may be used to recognise a program\'s specific log file formatting; a directory holds a file with these drivers, and programs can install their data in here as a modular extension; these modules define similar parameters to the above to select whether they might apply, and then still they may fail; drivers may share variables and/or specify aliases in other drivers; there is a special driver named "pass" that will match any free form, which by default would not have passed; drivers are applied in the order of occurrence in these options')

argprs.add_argument ('-m', '--mode',
		type=str,
		default=None,
		help='run in another mode than the default output to a pager; specify an http URI for an HTTP server; the authority part may be a localhost port, an address:port; or use a UNIX domain socket, or ssh: for an SSH subsystem')

argprs.add_argument ('-e', '--encoding',
		type=str,
		default='text',	#TODO# Dependent on --mode perhaps?
		choices=['text','html','csv'],
		help='code the output in a particular manner; html is an option, and so are csv and count; default is text for plain text display of selected lines from the log files')

argprs.add_argument ('-s', '--select',
		type=str,
		action='append',
		help='select one or more variables to display as they occur in the various lines of text; by default, all variables are shown; when multiple variables are used, they may be mentioned individually and/or separated by equals signs')

argprs.add_argument ('-where', '--where',
		type=str,
		default=[],
		action='append',
		help='apply a where-clause selection, requiring a pattern for a line that binds the given variable to the following value (after an = sign for a match or != for a non-match); multiple criteria may be entered to further constrain the selection')

argprs.add_argument ('-o', '--or',
		action='append_const',
		const=['OR'],
		dest='where',
		help='or-separation between where-clauses, which are normally conjugated; not that the combination and the lowest-level negation through != or = allows the expression of any logical combination')

argprs.add_argument ('-r', '--regexp',
		type=str,
		default=None,
		action='append',
		help='require free-form regexp in the line\'s freeform text')

argprs.add_argument ('-v', '--verbose',
		action="count",
		help='increase verbosity: suggest files that match the criteria; report when drivers miss lines that they would have liked to match; show log entries with variables explicitly marked inline')

# argprs.add_argument ('--help',
# 		action='store_true',
# 		help='show this information')

#NASTY# There must always be exactly one logfile when done this way
#NASTY# argprs.add_argument ('logfile',
#NASTY# 		default=None,
#NASTY# 		action='store',
#NASTY# 		help='explicit specification of logfile to gloss over; may specify more than one; defaults are introduced by most --driver specifications; in absense of those, /var/log/syslog and /var/log/messages are used')

if sys.argv [1:2] == ['--help']:
	argprs.print_help ()
	sys.exit (0)

warning = False

args = argprs.parse_args ()

#DEBUG# print 'Arguments:', args


#
# Interpret options, override defaults with more clever ones
#

if args.logfile is None:
	if args.driver is None:
		args.logfile = [ '/var/log/syslog', '/var/log/messages' ]
	else:
		pass #TODO# args.logfile from drivers

if args.driver is None:
	pass #TODO# default drivers, maybe ["pass"]


if args.select is None:
	var_names = None
else:
	var_names = []
	for seln in args.select:
		for seln_elm in seln.split ('='):
			if seln_elm != '':
				var_names.append (seln_elm)

conditions = []
for w in args.where:
	if w == ['OR']:
		conditions.append ( (None,None,None) )
	elif not '=' in w:
		sys.stderr.write ('Invalid where clause; use varname=value: ' + w + '\n')
		sys.exit (1)
	else:
		(wvar,wval) = w.split ('=', 1)
		same = True
		if wvar [-1:] == '!':
			wvar = wvar [:-1]
			same = False
		if wvar == '':
			sys.stderr.write ('You must supply a variable name in --where\n')
			sys.exit (1)
		conditions.append ( (wvar,wval,same) )

#
# Form regular expressions for the logfile lines
#

#TODO# Produce patterns to preselect under arguments

re_numeric = re.compile ('[0-9]+')
re_netstat = re.compile ('(?:tcp|udp|sctp):[0-9]+')

opt_month = set (['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'])
use_month = opt_month
re_month = '(' + '|'.join (use_month) + ')'
ky_month = ['month']

opt_day = set (range (1,32))
use_day = opt_day
re_day = '(' + '|'.join ( [str (d) for d in use_day ] ) + ')'
ky_day = ['day']
#CUTE:FIXED# re_day = '([1-9]|[12][0-9]|30|31)'

re_time = '([01][0-9]|2[0-3]:[0-5][0-9]:[0-5][0-9])'
ky_time = ['time']

re_tstamp = '((' + re_month + ' +' + re_day + ') ' + re_time + ')'
ky_tstamp = ['timestamp', 'date'] + ky_month + ky_day + ky_time

re_host = '([^ ]+)' if args.hostname is None else '(' + '|'.join (args.hostname) + ')'
ky_host = ['host']

use_pid = []
use_proc = []
for pid in args.pid:
	if pid [:1] == '/':
		pid = open (pid, 'r').read ().strip ()
	elif re_netstat.match (pid):
		sys.stderr.write ('No support yet for --pid ' + pid + '\n')
		sys.exit (1)
	if re_numeric.match (pid):
		use_pid.append (pid)
	else:
		use_proc.append (pid)
re_proc = '([^:]*[^:\]])' if use_proc == [] else '(' + '|'.join (use_proc) + ')'
re_pid = '(?:\[([0-9]+)\])?' if use_pid == [] else '\[(' + '|'.join (use_pid) + ')\]'
ky_proc = ['proc']
ky_pid = ['pid']

re_rest = '(.*)' if args.regexp is None else '(.*' + '.*|.*'.join (args.regexp) + '.*)'
ky_rest = ['logentry']

re_logline = re_tstamp + ' ' + re_host + ' ' + re_proc + re_pid + ': +' + re_rest + '\n'
ky_logline = ky_tstamp +       ky_host +       ky_proc + ky_pid +         ky_rest

print 'REGEXP', re_logline

seeline = re.compile (re_logline)

if var_names is None:
	var_names = ky_logline

#
# Take in the lines and parse them one by one
#
# TODO: Open logfiles in parallel, keep listening, merge output based on timestamps
# TODO: Support filename extensions
# TODO: Support zipped logfile content
#

for lf in args.logfile:
	try:
		with open (lf) as lfh:
			for lfl in lfh.readlines ():
				logged =  seeline.match (lfl)
				if not logged:
					if args.verbose:
						sys.stderr.write ('Unrecognised line format: ', lfl)
						warning = True
					continue
				linevars = dict (zip (ky_logline, logged.groups ()))
				where = True
				for (var,val,eq) in conditions:
					#DEBUG# print 'WHERE', (var,val,eq)
					if eq is None:
						if where:
							break
						else:
							where = True
					elif not linevars.has_key (var):
						where = False
					elif (linevars [var] == val) != eq:
						where = False
				if where:
					#DEBUG# print linevars
					for var in var_names:
						print var + '=' + linevars [var]
					print
	except Exception, e:
		sys.stderr.write ('Skipping non-accessible --logfile ' + lf + ' (' + str (e) + ')\n')
		warning = True
		pass

# Report any warning through the exit value
sys.exit (1 if warning else 0)

