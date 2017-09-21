#!/usr/bin/python

import os
#import signal
import threading
import atexit
import paramiko
import getpass
import re
import pdb
import time
#import telnetlib
import sys
#import smtplib
import json
import requests
#import ast
#import plotly
import pandas as pd
from texttable import Texttable
from tabulate import tabulate
from functools import wraps
from collections import OrderedDict
#from datetime import date

os.chdir("/Projects/scripts")

######################################
#   COLLECT INFO TO EXECUTE SCRIPT   #
######################################
search = ''
nemo_password = ''
dev_password = ''
device = ''
ip = ''
intf = ''
mlpe = ''
cust_name = ''                                  
port = ''                                   
port_speed = ''                                          
status = ''                                 
cable_id = ''                                                   
ipv6 = ''                                      
asn = ''                              
vlan = ''                               
tpid = ''                                        
product = ''                                      
rt_sr = ''
prompt = '\r\x1b[K\x1b[?1l\x1b>csw1.sv1(s1)#'
static_mac_expected_config = 'mac address-table static '
print"\n***Note: If you do typo then press \033[1;37;40m'ctrl+u'\033[0m to erase***\n"
while not nemo_password: # While the input given is an empty string
        print "Enter NEMO"
        nemo_password = getpass.getpass()

while not dev_password: # While the input given is an empty string
        print "Enter LDAP"
        dev_password = getpass.getpass()


input = raw_input("Due you want me to search NOCC(y/n): ")
if input == 'n':
	print "Will need info to run debugging through script\n"
	print"\n***Note: If you do typo then press \033[1;37;40m'ctrl+u'\033[0m to erase***\n"
	while not device: # While the input given is an empty string
        	device = raw_input("Enter your CX device name: ")
        	#device_check = re.sub(r'se\d\.\D\D\d+', "", device.lower())
        	#if device_check:
                #	print 'Invalid device name, Please re-enter device'
                #	device = ''

	while not intf: # While the input given is an empty string
        	intf = raw_input("Enter customer interface: ")
        	#intf_check = re.sub(r'\D\D-\d+/\d+/\d+', "", intf)
        	#if intf_check:
                #	print "Invalid interface name, Please re-enter device"
                #	intf = ''
        while not ip: # While the input given is an empty string
                ip = raw_input("Enter customer ip: ")

        while not mlpe: # While the input given is an empty string
                mlpe = raw_input("mlpe(y/n): ")

elif input == 'y':
        while not search: # While the input given is an empty string
                search = raw_input("Enter to search NOCC: ")


def noc_search(field):
	URL = "http://lxnoccas02.corp.equinix.com:9000/nocc-ui/search?searchFilter=all&searchText=%s&pageNumber=1&pageSize=100&userName=syiqbal"\
		%field
	r = requests.get(url = URL)
	return r
if bool(search):
	print "Please Wait! Searching NOCC for Customer Device/Interface/IPv4/IPv6"
	r = noc_search(search)
	data1 = r.json()
	data = data1['data']
	data = json.loads(data)
#	data = ast.literal_eval(data)
	df = pd.DataFrame(data['listSearchPort'])
	cols_to_keep = ['crossConnectSerialNumber','switchName','productName','portName','usage']
	print "\n\033[1;37;40m"
	print df[cols_to_keep]
	print "\033[0m\n"
	i = 0
	if len(data['listSearchPort']) > 1:
		range(len(data['listSearchPort']))
		i = raw_input("Enter one of the choices for IX device%s: " %(range(len(data['listSearchPort']))))
		i = int(i)
		print df[cols_to_keep].iloc[[i]]

	device = data['listSearchPort'][i]['switchName']
	cust_name = data['listSearchPort'][i]['accName']
	port = data['listSearchPort'][i]['portName']
	intf = filter(lambda x: '/' in x or x.isdigit(), port)
	port_speed = data['listSearchPort'][i]['portSpeed']      
	status = data['listSearchPort'][i]['status']
	ip = data['listSearchPort'][i]['ipAddress']
	cable_id = data['listSearchPort'][i]['crossConnectSerialNumber']
	ipv6 = data['listSearchPort'][i]['v6IpAddress']
	asn = data['listSearchPort'][i]['asn']
	vlan = data['listSearchPort'][i]['vlan']
	tpid = data['listSearchPort'][i]['tagProtocolId']
	product = data['listSearchPort'][i]['productName']
	if bool(data['listSearchClientPeers']):
		mlpe = data['listSearchClientPeers'][0]['mlpe']
		IX_client_peers = data['listSearchClientPeers'][0]['status']
	else:
		print "MLPE field not found in search response, Going to search from IPv4 address now"
		w = noc_search(ip)
	        w_data1 = w.json()
        	w_data = w_data1['data']
        	w_data = json.loads(w_data)
		mlpe = w_data['listSearchClientPeers'][0]['mlpe']
		IX_client_peers = w_data['listSearchClientPeers'][0]['status']


#############################################
#      EXECUTE SCRIPT WITH GIVEN INFO       #
#############################################
# log onto jumphost
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print "Intiating SSH connection to NEMO"
ssh.connect('172.16.19.1', username='syiqbal', password=nemo_password)
chan = ssh.invoke_shell()
while not device: # While the input given is an empty string
        device = raw_input("Enter your CX device name: ")
# logon to the end device
print "Intiating SSH connection to %s"%device
chan.send("ssh syiqbal@%s\n" %device)
buff = ''
while not buff.endswith(r'Password: '):
    resp = chan.recv(9999)
    buff += resp
    if buff.endswith(r'(yes/no)? '):
	chan.send("yes\n")
	buff = ''
	resp = chan.recv(9999)
	buff += resp

chan.send('%s\n'%dev_password)
buff = ''
while not buff.endswith('#'):
    resp = chan.recv(9999)
    buff += resp
print "Connection Successful to %s" %device
# Execute whatever command and wait for a prompt again.
# intf = '3/14'
my_dict = {}
mac_regex = re.compile(ur'(?:[0-9a-fA-F]:?){12}')
mac_regex_2 = re.compile(ur'(?:[\.0-9a-fA-F\.]:?){14}')


while not intf: # While the input given is an empty string
        intf = raw_input("Enter customer interface: ")
        #intf_check = re.sub(r'\D\D-\d+/\d+/\d+', "", intf)
        #if intf_check:
        #        print "Invalid interface name, Please re-enter device"
        #        intf = ''


print"\nGive me few seconds! Getting all the necessary information\n"

print "Checking Interface Ethernet %s config" %intf
chan.send('show run int e %s\n' %intf)
resp = ''
while 'description' not in resp:
	resp = chan.recv(9999)
sh_run_intf = resp.split('\r\n') 
if not isinstance(sh_run_intf, list):
	print "List not found"
	pdb.set_trace()
#my_list = [x.replace('\n', '') for x in sh_run_intf]
#keys = ['intf', 'desc', 'interval', 'vlan', 'mac_learning', 'access-list', 'lldp_tr', 'lldp_recv', 'broadcast', 'multicast']
#x = dict(zip(keys, my_list))
#y = dict(itertools.izip_longest(*[iter(my_list)] * 2, fillvalue=""))
#z = next((item for item in my_list if 'switchport' in item), None)

def list_dict(my_list):
	my_dict = dict(('vlan', item) for item in my_list if 'vlan' in item)
	my_dict['description'] = list(item.replace('   ','') for item in my_list if 'description' in item)  
	my_dict['access_list'] = list(re.findall(r'access-group (.*?) in', item)[0] for item in my_list if 'access-group' in item)
	my_dict['B_storm'] = list(item.replace('   ','') for item in my_list if 'storm-control broadcast' in item)  
	my_dict['M_storm'] = list(item.replace('   ','') for item in my_list if 'storm-control multicast' in item)
	my_dict['mac_learning'] = list(item.replace('   ','') for item in my_list if 'learning' in item)
	my_dict['lldp_transmit'] = list(item.replace('   ','') for item in my_list if 'lldp transmit' in item) 
	my_dict['lldp_receive'] = list(item.replace('   ','') for item in my_list if 'lldp receive' in item)               
	my_dict['load_interval'] = list(item.replace('   ','') for item in my_list if 'load-interval' in item)               
	my_dict['lag'] = list(item.replace('   ','') for item in my_list if 'channel-group' in item)
	
	return my_dict
channel = 'No Port-Channel Congifured'
sh_run_intf_dict = list_dict(sh_run_intf)
lag_present = False
if bool(sh_run_intf_dict['lag']):
	lag_present = True
	channel = sh_run_intf_dict['lag'][0]
	lag_digit = int(filter(str.isdigit, channel))
	print "Customer has lag Port-channel%s" %lag_digit
	print "Checking Port-channel%s config" %lag_digit 
	resp = ''
	chan.send('show run int po%s\n' %lag_digit)
	while 'description' not in resp:
        	resp = chan.recv(9999)
	sh_run_lag = resp.split('\r\n')
	sh_run_lag_dict = list_dict(sh_run_lag)
	acl_list = sh_run_lag_dict['access_list'][0]
	active_intf = 'Po%s'%lag_digit
	print "Checking Customer MAC Access List %s on interface %s" %(sh_run_lag_dict['access_list'][0], 'Po%s'%lag_digit)
	resp = ''
        chan.send("show mac access-lists %s\n" %sh_run_lag_dict['access_list'][0])
        while '00:00:00:00:00:00 any arp' not in resp:
                resp = chan.recv(9999)
        access_list_config = resp.split('\r\n')  
	print "Checking MAC Table Entries"
	resp = ''
        chan.send("sh mac address-table interface Port-Channel%s\n"%lag_digit)
        while r'Total Mac Addresses' not in resp:
                resp = chan.recv(9999)
        mac_table = resp.split('\r\n')
	print "Getting Customer VLAN and MAC info" 
	try:
		#intf_mac = re.findall(mac_regex_2, mac_table[5])
		ab = [re.findall(mac_regex_2,x) for x in mac_table]
		intf_mac = filter(None, ab)[0]
		sa = [re.findall(r' \d+ ',x) for x in mac_table]
		ga = filter(None, sa)[0]
		intf_vlan = int(re.search(r'\d+', ga[0]).group())
		#intf_vlan = re.findall(r'\d+', mac_table[5][:8])[0]
	except:
		print ("No MAC FOR INTERFACE IN CAM TABLE")
		pdb.set_trace()
	print "CHECKING STATIC MAC IS CONFIGURED ON INTERFACE P0%s"%lag_digit
	resp = ''
	chan.send("show run | grep '%s' | grep 'Channel%s' | grep 'static'\n"\
		   %(intf_mac[0],lag_digit))
        time.sleep(1)
        resp = chan.recv(9999)
        while not static_mac_expected_config in resp:             
                resp = chan.recv(9999)
        if prompt in resp:
                resp = resp.replace(prompt, '')
        remote = resp.split('\r\n')
#	remote.remove(prompt)
else:
        acl_list = sh_run_intf_dict['access_list'][0]
        active_intf = intf
	print "Checking Customer MAC Access List %s on interface %s" %(sh_run_intf_dict['access_list'][0], intf)
	resp = ''
	chan.send("show mac access-lists %s\n"%sh_run_intf_dict['access_list'][0])
        while '00:00:00:00:00:00 any arp' not in resp:
                resp = chan.recv(9999)
        access_list_config = resp.split('\r\n')
	print "Checking MAC Table Entries"
	resp = ''
        chan.send("sh mac address-table interface ethernet %s\n"%intf)
        while r'Total Mac Addresses' not in resp:
                resp = chan.recv(9999)
        mac_table = resp.split('\r\n')
	print "Getting Customer VLAN and MAC info"
	try:
		intf_mac = re.findall(mac_regex_2, mac_table[5])
		intf_vlan = re.findall(r'\d+', mac_table[5][:8])[0]
	except:
		print ("No MAC FOR INTERFACE IN CAM TABLE")
		pdb.set_trace()
	print "CHECKING STATIC MAC IS CONFIGURED ON INTERFACE %s"%intf
	chan.send("show run | grep '%s' | grep 't%s' | grep 'static'\n"%(intf_mac[0],intf))
	time.sleep(1)
	resp = chan.recv(9999)
        while not static_mac_expected_config in resp:
                resp = chan.recv(9999)
        if prompt in resp:
                resp = resp.replace(prompt, '')
        remote = resp.split('\r\n')       
#	remote.remove(prompt)
static_mac_config = remote[0]

if static_mac_expected_config in static_mac_config:
	print "Static mac %s config found on interface %s"%(intf_mac,'Po%s'%lag_digit if lag_present else intf)
	stat_mac_cfg_found = 'Yes'
else: 
	print "No Static mac %s config found on interface %s"%(intf_mac,'Po%s'%lag_digit if lag_present else intf)
	stat_mac_cfg_found = 'No'
print "Customer is in vlan %s" %intf_vlan
print "Customer has MAC %s" %intf_mac 

chan.send('exit\n')
time.sleep(0.5)
while True:
	resp = chan.recv(9999)
	if 'bash' in resp or 'nemo' in resp:	
		print"Disconnected from %s"%device
		break
	else:
		print"Going to exit from %s"%device
		chan.send('exit\n')
metro = device.split('.')[1]
metro_name = device.split('.')[1][:2]
metro_last = device.split('.')[1][1:][:1]
route_servers = ['ixrs1', 'ixrs2']
route_collector = ['rc1']

if mlpe.lower() == 'y':
	print "Customer has MLPE Config"
	rs_out = {}
	for index in range(len(route_servers)):
		# Login to Nemo and jump to Route servers
		ssh2 = paramiko.SSHClient()
		ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		print "Intiating SSH connection to NEMO"
		ssh2.connect('172.16.19.1', username='syiqbal', password=nemo_password)
		chan2 = ssh2.invoke_shell()
		buff = ''
		ibx = 1
		ixrs = '1' if index == 0 else '2'
		rt_sr = "ixrs%s.sv%d" %(ixrs,ibx)
		print "Intiating SSH connection to %s"%rt_sr
		chan2.send("ssh syiqbal@%s\n"%rt_sr)
		resp = chan2.recv(9999)
		buff += resp
		while not buff.endswith(r'password: '):
    			resp = chan2.recv(9999)
    			buff += resp
    			if buff.endswith(r'(yes/no)? '):
				chan2.send('yes\n')
				resp = chan2.recv(9999)
				buff += resp
			elif 'Could not resolve hostname' in buff:
				buff = ''
				if ibx < 10:
					ibx+=1
					rt_sr = "ixrs%s.%s%d" %(ixrs,metro_name,ibx)
					print("Trying to ssh %s"%(rt_sr))
					chan2.send("ssh syiqbal@ixrs%s.%s%d\n"%(ixrs,metro_name,ibx))
					resp = chan2.recv(9999)
					buff += resp
				elif ibx <= 12:
					ibx+=1
					rt_sr = "ixrs%s.%s%s"%(ixrs,metro_name,metro_last)
					print("Trying to ssh %s"%(rt_sr))
					chan2.send("ssh syiqbal@ixrs%s.%s%s\n"%(ixrs,metro_name,metro_last))
				elif ibx>11:
					print"Failed to login on ixrs%s"%ixrs
					pdb.set_trace()
		chan2.send('%s\n'%dev_password)
		print "Connection to %s Successfull"%(rt_sr)
		chan2.send('sudo su\n')
		buff = ''
		while not (r'password for') in buff:
    			resp = chan2.recv(9999)
    			buff += resp
		chan2.send('%s\n'%dev_password)
		time.sleep(0.5)
		chan2.send('cd /usr/local/mlpe/data\n')
		buff = ''
		with open('bird4.json') as json_data:
    			d = json.load(json_data)
			print d.keys()
			pdb.set_trace()
    			#print(d)
			
		
		chan2.send('grep "neighbor %s" /usr/local/mlpe/data/bird4.conf -A 600 -B 3\n'%ip)
		buff = ''
		while '# XDB:' not in buff:
        		resp = chan2.recv(9999)
        		buff += resp
		buff = buff.split('# XDB:')
		for item in buff:
			if 'neighbor ' + ip in item:
				rs_out['ixrs%s.%s.v4'%(ixrs,metro)] = item
				buff = ''
				break
		chan2.send('grep "neighbor %s" /etc/bird6.conf -A 600 -B 5\n'%ipv6)
		buff = ''
		v6 = 'neighbor %s as'%ipv6
                while v6 not in buff:
                        resp = chan2.recv(9999)
                        buff += resp
                buff = buff.split('# XDB:')
                for item in buff:
                        if 'neighbor ' + ipv6 + ' as' in item:
                                rs_out['ixrs%s.%s.v6'%(ixrs,metro)] = item
                                buff = ''
                                break 
		ssh2.close()
buff = ''	
rc_out = {}
# Login to Nemo and jump to Route servers         
ssh3 = paramiko.SSHClient()
ssh3.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print "Intiating SSH connection to NEMO"
ssh3.connect('172.16.19.1', username='syiqbal', password=nemo_password)
chan3 = ssh3.invoke_shell()
print "Intiating SSH connection to rc1.%s"%metro
chan3.send("ssh syiqbal@rc1.%s\n"%metro)
resp = chan3.recv(9999)
buff += resp
while not buff.endswith(r'password: '):
        resp = chan3.recv(9999)
        buff += resp
        if buff.endswith(r'(yes/no)? '):
                chan3.send('yes\n')
                resp = chan3.recv(9999)
                buff += resp
chan3.send('%s\n'%dev_password)
print "Connection to rc1.sv1 Successfull"
buff = ''
chan3.send('sudo su\n')
while not (r'password for') in buff:
	resp = chan3.recv(9999)
        buff += resp
chan3.send('%s\n'%dev_password)
chan3.send('grep "%s" /etc/bird.conf -A 600 -B 3\n'%ip)
buff = ''
while '# XDB:' not in buff:
	resp = chan3.recv(9999)
	buff += resp
buff = buff.split('# XDB:')
for item in buff:
        if 'bgp' in item:
        	rc_out['rc1.sv1'] = item
                break
#ssh3.close()

##############
# DRAW TABLE #
##############
print"\033[1;37;40m"
t = Texttable()
t.add_rows([['Customer', 'Info'],['Name',cust_name],['Device',device],['Cable ID',cable_id],['Vlan', intf_vlan], ['IP', ip],\
            ['Port-channel', channel],['Static MAC Configured on Switch',stat_mac_cfg_found],['MAC',intf_mac],\
            ['Access-List', acl_list],['Access-List Intf',active_intf],['MLPE', mlpe.upper()],['IPv6',ipv6],['Speed',port_speed],\
	    ['ASN',asn]])
print t.draw()
print"\033[0m"
print"\033[1;37;40m"
print "======================================="
print "\033[0m \033[2;30;47mIPv4 Route Collector Configuration\033[0m  \033[1;37;40m"
print "=======================================\033[0m"
print "\033[0m"
rc = rc_out.values()[0].split('\r\n')
for i in rc:
	print i
print"\033[1;37;40m"
print "===================================="
print "\033[0m \033[2;30;47mIPv6 Route Server Configuration\033[0m  \033[1;37;40m"
print "====================================\033[0m"
print "\033[0m"
pdb.set_trace()
rs = rs_out.values()[0].split('\r\n')
for k,v in rs_out.iteritems():
	print k
	print v



pdb.set_trace()
# This script prints out the switch's MAC address

# Create an EapiClient object...
#var eapi = new EapiClient();
# and form the eAPI request:
#var request = eapi.runCmds({'version': 1, 'cmds': ['show version']});

#request.done(function(result){
   # Hooray, the switch replied with data! Since we sent 1 command,
   # the data we care about is at result[0]. Extract the MAC address
   # and print it to the console:
#   var macAddr = result[0]["systemMacAddress"];
#   logMessage("The switch's system MAC addess is " + macAddr);
#});
