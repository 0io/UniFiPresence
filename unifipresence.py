#!/usr/bin/python
# Config File Location
#	default is /etc/unifipresence.conf
confFile = "/etc/unifipresence.conf"

#Imports
import json
import requests, requests.utils
import sys, traceback
import cookielib
import datetime

from ConfigParser import SafeConfigParser
from requests.packages.urllib3.exceptions import InsecureRequestWarning

config = SafeConfigParser()
config.read(confFile)

urlStShardbase = config.get('DEFAULT', 'urlStShardbase').strip("'\" \t")
urlUniFiBase = config.get('DEFAULT', 'urlUniFiBase').strip("'\" \t")
unUniFi = config.get('DEFAULT', 'unUniFi').strip("'\" \t")
pwUniFi = config.get('DEFAULT', 'pwUniFi').strip("'\" \t")
siteUniFi = config.get('DEFAULT', 'siteUniFi').strip("'\" \t")
cookieFile = config.get('DEFAULT', 'cookieFile').strip("'\" \t")
tmpFile = config.get('DEFAULT', 'tmpFile').strip("'\" \t")

#Setup
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
	sesUniFi = requests.Session()
	sesUniFi.verify = False
	jar = cookielib.MozillaCookieJar()
	try:
		jar.load(cookieFile, ignore_discard=True, ignore_expires=True)
		sesUniFi.cookies = jar
	except:
		loginUniFi(sesUniFi)
		pass # No cookie file, so login first
	
	try:
		url = urlUniFiBase + '/api/s/' + siteUniFi + '/stat/report/hourly.site'
		r = sesUniFi.get(url)
	except:
		sys.exit("UniFi Connection Test Failed")	

	if not r.status_code == requests.codes.ok:
		loginUniFi(sesUniFi)
	jar.save(cookieFile, ignore_discard=True, ignore_expires=True)

	try:
		url = urlUniFiBase + '/api/s/' + siteUniFi + '/stat/sta'
		r = sesUniFi.get(url)
	except:
		sys.exit("UniFi Client Listing Failed")
		
	clientsUniFi = r.json()
	# print clientsUniFi
	# for clientUniFi in clientsUniFi['data']:
		# print clientUniFi['mac']
	
# Read/Create temp status file
#	clientStatus = open(tmpFile,'w+')
# Loop through config 

	for clientConfig in config.sections():
		# print '\nSection:', clientConfig
		if not (config.has_option(clientConfig, 'appID') and config.has_option(clientConfig, 'AccessToken') and config.has_option(clientConfig, 'macAddr')):
			print datetime.datetime.now(), clientConfig, "must contain appID, AccessToken, and macAddr"
		else:
			appID = config.get(clientConfig, 'appID').strip("'\" \t")
			macAddr = config.get(clientConfig, 'macAddr').strip("'\" \t")
			AccessToken = config.get(clientConfig, 'AccessToken').strip("'\" \t")
			lastStatus = getLastStatus(appID)
			# print 'Client %s\nAppID %s\nLast Status %s\nMacAddr %s' % (clientConfig, appID, lastStatus, macAddr)
			# search clientsUniFi for macAddr
			currStatus = macSearch(macAddr, clientsUniFi)
			# print datetime.datetime.now(), "Current Status", currStatus
			setLastStatus(appID, currStatus)
			if not ( lastStatus and currStatus == lastStatus):
				print datetime.datetime.now(), 'Update SmartThings for ' + clientConfig + ' with status ' + currStatus
				updateSmartThings(urlStShardbase, appID, AccessToken, currStatus)
	
	#Defs
def getLastStatus(appID):
	try:
		with open(tmpFile, "r") as jsonFile:
			data = json.load(jsonFile)
		return data[appID]
	except:
		return False

def setLastStatus(appID, status):
	try:
		with open(tmpFile, "r") as jsonFile:
			data = json.load(jsonFile)
			data[appID] = status
	except:
		data = {}
		data[appID] = status
	with open(tmpFile, "w") as jsonFile:
		json.dump(data, jsonFile)
	
def loginUniFi(sesUniFi):
	url = urlUniFiBase + "/api/login"
	auth = {'username': unUniFi, 'password': pwUniFi}
	try:
		r = sesUniFi.post(url, data=json.dumps(auth))
	except requests.exceptions.RequestException as e:
		print e
		sys.exit("UniFi login failed")
	if not r.status_code == requests.codes.ok:
		print datetime.datetime.now(), "Login failed with status code ", r.status_code
		sys.exit(1)
	else:
		print datetime.datetime.now(), "UniFi logged in "
		
def macSearch(macAddr, clientsUniFi):
	for clientUniFi in clientsUniFi['data']:
		if clientUniFi['mac'].upper() == macAddr.upper():
			return 'Present'
	return 'Absent'

def updateSmartThings(urlStShardbase, appID, AccessToken, currStatus):
	if currStatus == 'Present':
		status = 'home'
	else:
		status = 'away'
	url = urlStShardbase + "/api/smartapps/installations/" + appID + "/Phone/" + status + "?access_token=" + AccessToken
	# print url
	try:
		r = requests.get(url)
	except requests.exceptions.RequestException as e:
		print e
		sys.exit("SmartThings Update Failed")
	if not r.status_code == requests.codes.ok:
		print datetime.datetime.now(), "SmartThings update failed with status code ", r.status_code
		if int(r.status_code) == '500':
			print datetime.datetime.now(), "Is this really a Virutal Presence Sensor?"
	# else:
		# print datetime.datetime.now(), "SmartThings Updated"
	
if __name__ == '__main__':
	main()
