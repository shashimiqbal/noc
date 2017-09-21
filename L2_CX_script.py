#!/usr/bin/python


import os
import sys
import signal
import threading
import atexit
import paramiko
import getpass
import re
import pdb
import time
from functools import wraps

"""
The script is going to check interface configuration
	1) Check if customer has configured lag
	2) Check if interface/lag state 'Up'
	3) Grab Routing instance, bridge info from lag/intf 
	4) Check mac entries in the bridge domain
	5) If any mac is missing based on config or traffic, script will suggest possible root cause
	6) At the end delivers all the necessary read info for user to answer customer queries	
	7) Script has watchdog to time script and a decorator to monitor time running any function
"""


class Watchdog():
    def __init__(self, timeout=10):
        self.timeout = timeout
        self._t = None

    def do_expire(self):
        os.kill(os.getpid(),signal.SIGKILL)

    def _expire(self):
        print("\nWatchdog expire")
        self.do_expire()

    def start(self):
        if self._t is None:
            self._t = threading.Timer(self.timeout, self._expire)
            self._t.start()

    def stop(self):
        if self._t is not None:
            self._t.cancel()
            self._t = None

    def refresh(self):
        if self._t is not None:
             self.stop()
             self.start()


wd = Watchdog(10)           


class myssh:

    def __init__(self, host, password, port = 22):
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, port=port, password=password)
        atexit.register(self.client.close)
        self.output = []
	self.port_speed = None

    def __call__(self, command):
        stdin,stdout,stderr = self.client.exec_command(command)
        sshdata = stdout.readlines()
        self.output.append(sshdata)
#       for line in sshdata:
#            print(line)

def fn_timer(function):
    '''Decorator to measure time spent on running any function'''
    @wraps(function)
    def function_timer(*args, **kwargs):
        t0 = time.time()
        result = function(*args, **kwargs)
        t1 = time.time()
        print ("Total time running %s: %s seconds" %
               (function.func_name, str(t1-t0))
               )
        return result
    return function_timer


port_config = []
vlan_tags = []
cust_lag = []
vc_tpid_vlan = {}
BD_RI = {}
VC = {}
info_list = []
l2 = {}
vcs_stats = {}
space = ""
vc_intf_stats = ()
intf_state = []
port_speed = None
allowed_TPID = None
intf_speed = None
device = ''
password = ''
intf = ''
regex = re.compile(ur'(?:[0-9a-fA-F]:?){12}')
coloumn = (2 * '|')
row = ((2 * '--' + '\n') * 2)
if bool(sys.argv[1:]):
	argmnts = sys.argv[1:]
	user = argmnts[0]
	device = argmnts[1]
	password = argmnts[2]
	intf = argmnts[3]
print"\n***Note: If you do typo then press \033[1;37;40m'ctrl+u'\033[0m to erase***\n"
while not device: # While the input given is an empty string
	device = raw_input("Enter your CX device name: ")
    	device_check = re.sub(r'se\d\.\D\D\d+', "", device.lower())
	if device_check:
		print 'Invalid device name, Please re-enter device'
		device = ''
		
while not password: # While the input given is an empty string
	password = getpass.getpass()
	    
while not intf: # While the input given is an empty string
    	intf = raw_input("Enter customer interface: ")
	intf_check = re.sub(r'\D\D-\d+/\d+/\d+', "", intf)	
	if intf_check:
		print "Invalid interface name, Please re-enter device"
		intf = ''
		
#wd.start()
#remote = myssh(device, password)
#wd.stop()
remote = None
run = 'y'
while run == 'y':
	if not bool(remote):
		wd.start()
		remote = myssh(device, password)
		wd.stop()
	wd.start()
	print"\nGive me few seconds! Getting all the necessary information\n"
	remote('show interface %s' %intf)
	wd.refresh
	intf_info = remote.output[-1]
	remote('show configuration | match %s | display set' %intf)
	wd.stop()
	intf_configs = remote.output[-1]

	def configs(info):
		if len(info) > 5: 
			if 'Up' in info[0]:
				intf_state = 'Up'
			else:
				print"Customer interface %s is not 'Up' state, Please check and run the script"%intf
				intf_state = 'Down'
			for inf in info[:5]:
				if 'description' in inf.lower():
					port_description = inf[15:][:-1]
			equinix_side_mac = info[9][19:][:-38]
			Last_flapped = info[10][19:][:-1]
			for item in info:
				if 'Input rate' in item:
					input_rate = info[11][19:][:-1]
					input_rate_digit = int(input_rate.split(' ')[2].replace('(',''))
					continue
				if 'Output rate' in item:
					output_rate = item[19:][:-1]
					break
			for i in info[:6]:	
				if 'mtu' in i.lower():
					xyz = ''
					xyz = i.lower().split(',')[1]
					if bool(filter(str.isdigit,xyz)):
						mtu = filter(str.isdigit,xyz)
					elif 'unlimited' in xyz:
						mtu = 'unlimited'
					else:
						print "Cannot find mtu, Please check function named 'configs'"
					
				if 'peed' in i: 
					intf_values = i.split(',')        	
					for intf_value in intf_values:
						if 'peed' in intf_value:
							intf_speed = intf_value[8:]
							#intf_speed = info[3].split(',')[4][8:]
							#continue
		else:
			print "Incorrect interface, Please! Check if interface exists on device"
			wd.do_expire()
		return intf_state, port_description, equinix_side_mac,Last_flapped, input_rate,output_rate, input_rate_digit, mtu, intf_speed

	intf_state, port_description, equinix_side_mac,Last_flapped, input_rate,output_rate,input_rate_digit, mtu, intf_speed = configs(intf_info)


	for index in range(16,len(intf_info)):
		if 'Logical interface' in intf_info[index] and '.32767' not in intf_info[index]:
			Logical_Interface = intf_info[index].replace('  Logical interface ','').split(' ')[0]
			print"Getting VC %s input/output pkts" %Logical_Interface
			for vc_index in range(index,index+6):
				if 'Input packets' in intf_info[vc_index]:
					vc_intf_stats = ()
					input_pkts = intf_info[vc_index][20:][:-1]
					vc_intf_stats = vc_intf_stats + (input_pkts,)
					vcs_stats[Logical_Interface] = vc_intf_stats
					continue
				
				if 'Output packets' in intf_info[vc_index]:
					output_pkts = intf_info[vc_index][20:][:-1]
					vc_intf_stats = vc_intf_stats + (output_pkts,)
					vcs_stats[Logical_Interface] = vc_intf_stats
					continue

	for intf_config in reversed(intf_configs):
		if 'ae' in intf_config.split(' ')[2]:
			cust_lag = intf_config.split(' ')[2]
			remote('show configuration | match %s | display set'%cust_lag)
			lag_configs = remote.output[-1]
			for lag_config in lag_configs[10:]:
				if 'vlan-tags' in lag_config:
					port_vlan_tags = lag_config[15:][:-1].replace(' unit ','.')
					port_vlan_tags = port_vlan_tags.split(' vlan-tags ')
					vc_tpid_vlan[port_vlan_tags[0]] = port_vlan_tags[1]
					continue
				if 'BD-' in lag_config:
					split_lag_config = lag_config.split(' ')
					key = lag_config.split(' ')[6].replace('\n', '')
					if len(key) > len(space):
						for i in range(len(key)):
							space = space + " "
					BD_RI[split_lag_config[4]] = split_lag_config[2]
					VC[key] = BD_RI
					BD_RI = {}
					continue
			break
		else:
			vc_intf = intf_config.split(' ')[2]
			if 'vlan-tags' in intf_config:
				port_vlan_tags = intf_config[15:][:-1].replace(' unit ','.')
				port_vlan_tags = port_vlan_tags.split(' vlan-tags ')      
				vc_tpid_vlan[port_vlan_tags[0]] = port_vlan_tags[1]
				continue
			if 'BD-' in intf_config:
				split_intf_config = intf_config.split(' ')
				key = intf_config.split(' ')[6].replace('\n', '')
				if len(key) > len(space):
					for i in range(len(key)):
						space = space + " "
				BD_RI[split_intf_config[4]] = split_intf_config[2]
				VC[key] = BD_RI
				BD_RI = {}
				continue



	wd.start()
	remote('show configuration interfaces %s' % (cust_lag if bool(cust_lag) else intf))
	wd.refresh()
	show_config_intfs = remote.output[-1]
	remote('show interface %s' % (cust_lag if bool(cust_lag) else intf))                
	wd.stop()
	show_intf = remote.output[-1]

	def lag_intf_info(show_lag,lag):
		if bool(lag):                
			equinix_side_mac = show_lag[8][19:][:-38]                
			lag_mtu = show_lag[3].split(',')[1][6:]
			lag_Last_flapped = show_lag[9][19:][:-1]
			if 'Up' in show_lag[0]:
				lag_state = 'Up'
			else:
				print"Customer lag %s is not 'Up' state, Please check and run the script again!" %lag
				lag_state = 'Down'
			for item in show_lag[3].split(','):
				if 'peed' in item:
					lag_speed = item[8:]

		return equinix_side_mac,lag_mtu,lag_Last_flapped,lag_state,lag_speed
	if bool(cust_lag):
		equinix_side_mac,lag_mtu,lag_Last_flapped,lag_state,\
			lag_speed = lag_intf_info(show_intf,cust_lag)

	#@fn_timer
	def port_attributes(show_config_ints):
		port_speed = None
	#	allowed_TPID = show_config_ints[12][26:][:-4]
		for port_attribute in show_config_ints[17:]:
			if 'vlan-tags' in port_attribute:
				vlan_tags.append(port_attribute[14:][:-2])
				continue
			if 'speed' in port_attribute:
				port_speed = port_attribute.replace("speed ", "")
				port_speed = port_attribute.replace("link-", "")
				continue	
		port = {'port_description': port_description,'allowed_TPID':allowed_TPID, 'port_speed':port_speed,'vlan_tags': vlan_tags,'mtu': mtu}
		return port

	def logical_intfs(vc_info):
		#vc_outer_vlan = vc_info[1].split(' ')[10]
		vc_vlan = vc_info[1]
		vc_vlan = vc_vlan[vc_vlan.find("[")+1:vc_vlan.find("]")]  
		vc_vlan = (vc_vlan.split(' '))
		vc_vlan = [x for x in vc_vlan if x]
		if len(vc_vlan) == 2:	
			vc_outer_vlan='outer:'+vc_vlan[0]+':match S-tag on CSP portal,'+'inner:'+vc_vlan[1]+':match C-tag on CSP Portal'
		
		else:
			vc_outer_vlan = 'S-TAG:outer:' + vc_vlan[0] + ",inner:We don't care"
		#vc_outer_vlan = vc_vlan[vc_vlan.find("[")+1:vc_vlan.find("]")]
		input_pkts = vc_info[2][20:][:-1] 
		output_pkts = vc_info[3][20:][:-1]
		return vc_outer_vlan, input_pkts, output_pkts
	csp_mac_intf = None
	for k, v in VC.iteritems():
		RI = v.values()[0]
		BD = v.keys()[0]
		print "Checking mac for VC interfaces %s"%(k)
		remote('show bridge mac-table instance %s bridge-domain %s'
		       % (RI, BD))
		mac_out = remote.output[-1]
		if '\n' in mac_out:
		    mac_out.remove('\n')
		macs = []
		cust_mac = []
		csp_mac = []
		for index in range(len(mac_out)):
			mac = re.findall(regex, mac_out[index])
			if bool(mac):
				macs.append(mac[0])
				if k in mac_out[index]:
					cust_mac.append(mac[0])
				else:
					csp_mac.append(mac[0])
					if not mac_out[index].split(' ')[11].isspace():
						csp_mac_intf = mac_out[index].split(' ')[11]
					
		l2['RI'] = RI
		l2['BD'] = BD
		l2['cust_mac'] = cust_mac
		l2['csp_mac'] = csp_mac
		l2['macs'] = macs
		l2['interface'] = k
		l2['csp_mac_intf'] = csp_mac_intf
		info_list.append(l2)
		l2 = {}

	port = port_attributes(show_config_intfs)

	print("\033[1;37;40m==================================================================================\033[0m")
	if bool(cust_lag):
		print "Customer has %s configured on interface: %s" %(cust_lag, intf)
	print("\033[1;37;40m==================================================================================\033[0m")
	print "Customer has total %s L2_CX VC" %len(info_list)
	print("\033[1;37;40m==================================================================================\033[0m")
	print "\033[2;30;47mCustomer %s%s configuration\033[0m" %(intf," & %s"%cust_lag if bool(cust_lag) else "")
	print '\n\033[0;37;44mport description%s     \033[0m %s\n'% (space,port['port_description'])
	print '\n\033[0;37;44m%s state%s       \033[0m %s\n'% (intf, space,intf_state)
	print '\n\033[0;37;44m%s Last flapped%s\033[0m %s\n'% (intf,space,Last_flapped)

	if bool(cust_lag):
		print '\n\033[0;37;44m%s    state%s       \033[0m %s\n'% (cust_lag, space,lag_state)
		print '\n\033[0;37;44m%s   Last flapped %s\033[0m %s\n'% (cust_lag,space,lag_Last_flapped)
			
	for k, v in vc_tpid_vlan.iteritems(): 
		vc_str_len = len(k)
		space = ""
		for i in range(vc_str_len):
			space = space + " "
		if 'outer' in v:
			print '\033[0;37;44m%s outer tpid vlan info\033[0m %s\n' %(k, re.sub(r'.* outer ','', v))
		else:
			print "VC:%s 'No outer tag info found, Please check config is pushed" %k
		if 'inner' in v:
			print '\033[0;37;44m%s inner tpid vlan info\033[0m %s\n'%(k,re.sub(r'.* inner ','', v))
		else:
			print "\033[0;37;44m%s inner tpid vlan info\033[0m Not given, so, we don't care because"%k 
			print "\033[0;37;44m         %s            \033[0m 1. Either they are using dot1q OR"%space
			print "\033[0;37;44m         %s            \033[0m 2. If QinQ, Customer should match with"%space
			print"\033[0;37;44m         %s            \033[0m   CSP expected vlan(Check CSP Portal)\n"%space
	print '\033[0;37;44mmtu      %s            \033[0m %s\n' % (space, port['mtu'])
	print '\033[0;37;44mport_speed %s          \033[0m %s\n'%(space, port['port_speed'] if bool(port['port_speed']) else "Default speed i.e. %s" %intf_speed)
	if bool(cust_lag):
		print '\033[0;37;44mlag_speed %s           \033[0m %s\n' %(space, lag_speed)
	print("\033[1;37;40m==================================================================================\033[0m")
	print "\033[2;30;47mCustomer %s traffic info is as follows\033[0m"%intf
	print"\033[0;37;40mInput traffic rate info:\033[0m"
	if input_rate_digit == 0:
	    print("\t\t     \033[5;37;41m***Root Cause***\033[0m")
	    if 'Down' == intf_state:
		print"\t\033[1;37;40mCustomer Interface is Down. Please debug Layer-1\033[0m"
	    elif bool(cust_lag) and 'Down' == lag_state:
		print"\t\033[1;31;40mLACP is Down. Please ask Customer to either configure LACP OR\033[0m"
		print "\t\033[1;31;40mRemove LACP on Equinix SVC through NOCC\033[0m"

	    else:
		print "\t\033[1;31;40mWe are not receiving any traffic from Customer\033[0m"
		print "\t\033[1;31;40mPlease, ask customer to start sending traffic\033[0m"
	else:
	    print("\033[1;37;40m\tInterface %s input rate is %s\033[0m")% (intf, input_rate)
	if 'Up' == intf_state:
		print "\n\033[0;37;40mOutput traffic rate info:\033[0m"
		print("\t\033[1;37;40mInterface %s output rate is %s\033[0m")% (intf, output_rate)
	print("\033[1;37;40m==================================================================================\033[0m")

	for k, v in vcs_stats.iteritems():
		if bool(cust_lag):
			for info in info_list:
				if info['interface'].replace(cust_lag, '') == k.replace(intf, ''):
					print "\033[2;30;47mCustomer vc %s pkts info:\033[0m" %(info['interface'])
					print"\tinput pkts: %s" %(v[0])
					print "\toutput pkts: %s" %(v[1])
					print("\033[1;37;40m==================================================================================\033[0m")
					

		else:
			print "\033[2;30;47mCustomer vc %s pkts info:\033[0m" %k
			print "\tinput pkts: %s" %v[0]
			print "\toutput pkts: %s" %v[1]
			
	for info in range(len(info_list)):
		print("\033[1;37;40m==================================================================================\033[0m")
		print("\033[2;30;47mVC: %s info is as follows:\033[0m")%(info_list[info]['interface'])
		print "\tCustomer Routing instance    : \033[1;37;40m%s\033[0m" %info_list[info]['RI']
		print "\tCustomer Bridge doman        : \033[1;37;40m%s\033[0m" %info_list[info]['BD']
		print "\tCustomer should learn mac    : \033[1;37;40m['CSP MAC Only']\033[0m"
		if bool(info_list[info]['macs']):
			if not bool(info_list[info]['cust_mac']):
				print("\t\t  \033[5;37;41m***Possible Issue***\033[0m")
				print "\t\033[1;31;40mNo Customer mac address found on vc:%s"%info_list[info]['interface']
				
				if input_rate_digit > 0:
					print("\t\t\033[5;37;41m***Possible Root Cause***\033[0m")
					print "\t\033[1;31;40mCustomer Input traffic rate found is '%s'\033[0m"%input_rate
					print "\t\033[1;31;40mCustomer mac most probably not learnt due to vlan mismatch\033[0m"
					
				elif 'Down' == intf_state:
					print("\t\t    \033[5;37;41m***Root Cause***\033[0m")
					print"\t\033[1;37;40mCustomer Interface is Down. Please debug Layer-1\033[0m"
				elif bool(cust_lag) and 'Down':
					print("\t\t    \033[5;37;41m***Root Cause***\033[0m")
			                print"\t\033[1;31;40mLACP is Down. Please ask Customer to either configure LACP OR\033[0m"
                			print "\t\033[1;31;40mRemove LACP on Equinix SVC through NOCC\033[0m"

				else:
					print("\t\t     \033[5;37;41m***Root Cause***\033[0m")
					print '\t\033[0;31;40mCustomer Input traffic rate found is zero\033[0m'
					print '\t\033[0;31;40mPlease ask Customer to send traffic\033[0m'
			else:
				print "\tCustomer mac address         : \033[1;37;40m%s\033[0m"%info_list[info]['cust_mac']
			if not bool(info_list[info]['csp_mac']):
				print("  \t\t\033[5;37;41m***Possible Issue***\033[0m")
				print "\t\033[1;31;40mNo CSP mac address found\033[0m"
			else:
				print "\tCSP side mac address         : \033[1;37;40m%s\033[0m"%info_list[info]['csp_mac']
				remote('show version | match Hostname')
				local_cx_dev = remote.output[-1][0].replace('Hostname: ','')[:-5]
				if not bool(info_list[info]['csp_mac_intf']):
					remote('show route table %s evpn-mac-address %s active-path | match ae'%(info_list[info]['RI'], info_list[info]['csp_mac'][0]))
					csp_evpn = remote.output[-1]
					csp_evpn_lag = csp_evpn[-1].split(' via ')[-1][:-1]
					remote('show interfaces %s | match Desc'%(csp_evpn_lag))
					csp_lag_desc = remote.output[-1][0]
					cx_devs = re.findall(r"se|SE\d\.\D\D\d+",csp_lag_desc)
					cx_devs = [x.lower() for x in cx_devs]
					cx_devs = list(filter(lambda x: x != local_cx_dev, cx_devs))
				else: 
					csp_evpn_lag = info_list[info]['csp_mac_intf']
					cx_devs = [local_cx_dev]
				for cx_dev in cx_devs:
					if local_cx_dev.lower() != cx_dev.lower():
						info_list[info]['csp_dev'] = cx_dev.lower()
						csp_ssh = myssh(cx_dev.lower(), password)
						csp_ssh('show bridge mac-table instance %s bridge-domain %s'%(info_list[info]['RI'],info_list[info]['BD']))
						csp_mac_out = csp_ssh.output[-1]
						for mac in csp_mac_out[8:]:
							if info_list[info]['csp_mac'][0] in mac:
								csp_vc = mac.split(' ')[11]
								csp_intf = csp_vc.split('.')[0]
								info_list[info]['csp_vc'] = csp_vc
								print"\n\033[2;30;47mCustomer VC %s CSP info:\033[0m"\
									%info_list[info]['interface']
								print "\tCSP Device                   : \033[1;37;40m%s\033[0m"\
								%info_list[info]['csp_dev']
								print "\tCSP VC Interface             : \033[1;37;40m%s\033[0m"\
								%info_list[info]['csp_vc']
								csp_ssh('show configuration interfaces %s'%csp_intf)
								show_config_csp = csp_ssh.output[-1]
								csp_port = port_attributes(show_config_csp)
								csp_ssh('show interface %s'%csp_intf)
								csp_intf_info = csp_ssh.output[-1]
								csp_port_description=csp_intf_info[2][15:][:-1]
								if 'Up' in csp_intf_info[0]:
									intf_state = 'Up'
								else:
									print"Customer interface %s is not 'Up' state, Please check and run the script again"%(csp_intf)
									intf_state = 'Down'

								if 'ae' not in csp_intf:
									csp_intf_state,csp_port_description,\
									csp_equinix_side_mac,csp_Last_flapped,\
									csp_input_rate,csp_output_rate,\
									csp_input_rate_digit, csp_mtu,\
									csp_intf_speed = configs(csp_intf_info)
									csp_ssh('show interface %s'%csp_vc)
									csp_vc_info = csp_ssh.output[-1]  
									csp_vc_outer_vlan,csp_input_pkts,\
									csp_output_pkts  = logical_intfs(csp_vc_info)		
								else: 
							
									csp_intf_state,csp_port_description,\
									csp_equinix_side_mac,csp_Last_flapped,\
									csp_input_rate,csp_output_rate,\
									csp_input_rate_digit, csp_mtu,\
									csp_intf_speed = configs(csp_intf_info)
									csp_ssh('show interface %s'%csp_vc)
									csp_vc_info = csp_ssh.output[-1]
									csp_vc_outer_vlan,csp_input_pkts,\
									csp_output_pkts  = logical_intfs(csp_vc_info)

									csp_equinix_side_mac,csp_mtu,\
									csp_Last_flapped,csp_intf_state,\
									csp_intf_speed = lag_intf_info(csp_intf_info,csp_intf)
								
								print"\n\033[7;33;40m\t\t\t*********Customer VC %s Schematic Topology**********\033[0m\n"\
									%info_list[info]['interface']
								print "\033[1;37;40mBuyer:%s--%s-%s\033[0m\033[2;30;47m%s-%s\033[0m\033[1;37;40m%s-%s--%s:CSP\033[0m\n"\
									%(info_list[info]['interface'],\
									[(k, vc_tpid_vlan[k]) for k in vc_tpid_vlan.keys() if k == info_list[info]['interface']][0][1],\
									coloumn,\
									local_cx_dev.lower(),\
									info_list[info]['csp_dev'].lower(),\
									coloumn,\
									csp_vc_outer_vlan,\
									info_list[info]['csp_vc'])
								
								print "\033[2;30;47mCSP Interface %s configuration\033[0m" %(csp_intf)
								print '\n\033[0;37;44mport description%s      \033[0m %s\n'% (space,csp_port_description)
								print '\n\033[0;37;44m%s state%s        \033[0m %s\n'% (csp_intf, space,csp_intf_state)
								print '\n\033[0;37;44m%s Last flapped%s \033[0m %s\n'% (csp_intf,space,csp_Last_flapped)			            
								print '\n\033[0;37;44m%s tpid vlan info    \033[0m %s\n'\
									% (info_list[info]['csp_vc'],csp_vc_outer_vlan)
								print '\n\033[0;37;44m%s mtu%s          \033[0m %s\n'% (csp_intf,space,csp_mtu)
								print '\n\033[0;37;44m%s speed%s        \033[0m %s\n'% (csp_intf,space,csp_intf_speed)
					else:
						print"\033[2;30;47mCustomer VC %s CSP info:\033[0m"\
						      %info_list[info]['interface']					
						print "\tCSP On Same Device           : \033[1;37;40m%s\033[0m"\
							%local_cx_dev.lower()
						csp_vc = info_list[info]['csp_mac_intf']
						print "\tCSP VC Interface             : \033[1;37;40m%s\033[0m"\
						       %csp_vc
						csp_intf = csp_vc.split('.')[0]
						
						remote('show configuration interfaces %s'\
							%(csp_intf))
						show_config_csp = remote.output[-1]
						csp_port = port_attributes(show_config_csp)
						info_list[info]['csp_vc'] = csp_vc
						remote('show interface %s'%csp_intf) 
						csp_intf_info = remote.output[-1]
						if 'ae' not in csp_intf:
							csp_intf_state,csp_port_description,\
							csp_equinix_side_mac,csp_Last_flapped,\
							csp_input_rate,csp_output_rate,\
							csp_input_rate_digit, csp_mtu,\
							csp_intf_speed = configs(csp_intf_info)
							remote('show interface %s'%csp_vc)
							csp_vc_info = remote.output[-1]
							csp_vc_outer_vlan,csp_input_pkt,\
							csp_output_pkts  = logical_intfs(csp_vc_info)
						else:
							csp_intf_state,csp_port_description,\
							csp_equinix_side_mac,csp_Last_flapped,\
							csp_input_rate,csp_output_rate,\
							csp_input_rate_digit, csp_mtu,\
							csp_intf_speed = configs(csp_intf_info)
							remote('show interface %s'%csp_vc)
							csp_vc_info = remote.output[-1]
							csp_vc_outer_vlan,csp_input_pkts,\
							csp_output_pkts  = logical_intfs(csp_vc_info)

							csp_equinix_side_mac,csp_mtu,\
							csp_Last_flapped,csp_intf_state,\
							lag_speed = lag_intf_info(csp_intf_info,csp_intf)
						
						print"\n\033[7;33;40m\t\t\t*********Customer VC %s Schematic Topology**********\033[0m\n"\
							%info_list[info]['interface']
						print "\033[1;37;40mBuyer:%s--%s-%s\033[0m\033[2;30;47m%s\033[0m\033[1;37;40m%s-%s--%s:CSP\033[0m\n"\
							%(info_list[info]['interface'],\
							[(k, vc_tpid_vlan[k]) for k in vc_tpid_vlan.keys() if k == info_list[info]['interface']][0][1],\
							coloumn,\
							local_cx_dev.lower(),\
							coloumn,\
							csp_vc_outer_vlan,\
							info_list[info]['csp_vc'])


						print "\033[2;30;47mCSP Interface %s & VC %s configuration\033[0m"\
						       %(csp_intf, csp_vc)
						print'\n\033[0;37;44mport description%s      \033[0m %s\n'\
						       %(space,\
							 csp_port_description if bool(csp_port_description) else "No Config,\
							 Ask Customer to create VC or check CXP if VC is created")
						print '\n\033[0;37;44m%s state%s        \033[0m %s\n'\
							%(csp_intf, space,\
							  csp_intf_state if bool(csp_intf_state) else 'Check Layer-1, \
							  if LAG then configure LAG on customer side')
						print '\n\033[0;37;44m%s Last flapped%s \033[0m %s\n'% (csp_intf,space,csp_Last_flapped)
						print '\n\033[0;37;44m%s tpid vlan info      \033[0m %s\n'\
							%(info_list[info]['csp_vc'],csp_vc_outer_vlan)
						print '\n\033[0;37;44m%s mtu%s          \033[0m %s\n'% (csp_intf,space,csp_mtu)
						print '\n\033[0;37;44m%s speed%s      \033[0m %s\n'% (csp_intf,space,csp_intf_speed)


		else:
			print("\t\t\033[5;37;41m***Possible Root Cause***\033[0m\033[0m")
			print "\t\033[1;31;40mNo mac addresses are learnt on this bridge-domain.\033[0m"
			print "\t\033[1;31;40mNext Steps to follow:\033[0m"
			print "\t\033[1;31;40mmatch vlan tag and tpid %s\033[0m" %info_list[info]['interface']
		if bool(info_list[info]['csp_mac']) & bool(info_list[info]['cust_mac']): 
			print("\033[4;37;44mSteps to check(if still not able to reach CSP on VC:%s)\033[0m")%(info_list[info]['interface'])
			print "If Customer still cannot ping CSP side ip address then"
			print "possible issue on this VC:%s would be:"%(info_list[info]['interface'])
			print " 1)Check MAC: Customer mac matches with expected mac"
			print "  a.If not, ask customer to initate ping to csp ip and run script again to see if new mac is learn't"
			print "  b.If after ping, still expected customer mac is not learn't, please escalate"
			print " 2)Check TPID: Match TPID on Equinix and Customer side"
			print " 3)Check CSP portal: Customer may have service not Up/Available/Provisioned on CSP portal"
			print " 4)If QinQ, Check inner vlan:Customer may be sending incorrect inner vlan tag to CSP"
			print "  a.Ask Customer for inner vlan & Confirm on CSP portal for matching vlan"
	print("\033[1;37;40m========================================================================================\033[0m")
	print("\033[1;37;40m========================================================================================\033[0m")
	print("\033[1;37;40m \t\t\t\t\tNote\033[0;37;40m \n")
	print "If still issue exists, Please check counters for exact VC on both CSP & Customer side" 
	print " Steps to check errors on VC:"
	print "  Copy the service-key and use EPN tool to know CSP side device and VC"
	print "   a.On Customer device, use command 'monitor interface <customer side exact vc>'"
	print "   b.On CSP device, use command 'monitor interface <csp side exact vc>'"
	print "   c.Check if any errors are incrementing in large chunks, if yes escalate"
	print "   d.Check traffic input/output rates on both sides"
	print "     Note:'Input bytes rate on one side(Customer side) should be close to output"
	print "     bytes rate on other side(CSP side) and vice versa'"


	print("\033[1;33;40m\t\t\t=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=\033[0m")
	print("\033[1;33;40m\t\t\t=        End of Script!       =\033[0m")
	print("\033[1;33;40m\t\t\t=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=\033[0m")
	print("\033[1;37;40m=======================================================================================\033[0m")
	while True:
		run = raw_input("Do you want to run script again?(y/n): ")
		print("\033[1;37;40m=======================================================================================\033[0m")
		if run.lower() == "y" or run.lower() == 'n':
			break
        	else:
			print "Invalid Entry, Please try again!"
			run == True
			#run = raw_input("Do you want to run script again?(y/n): ")


print("\033[1;33;40m\t\t\t=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=\033[0m")
print("\033[1;33;40m\t\t\t=           Good Bye!         =\033[0m")
print("\033[1;33;40m\t\t\t=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=\033[0m")
print """\n\t"Suggestions or Improvements please send e-mail to syiqbal@equinix.com"\n"""
