#!/usr/bin/python -u
# -*- coding: utf-8 -*-

import bisect
import logging
import re
import requests
import argparse

class color:
 BOLD = '\033[1m'
 UNDERLINE = '\033[4m'
 END = '\033[0m'

# -----------------------------------------------------------------------------
# Locations and Constants

VERSION = "2.1.1"
INTEL_HEADER = """#fields\tindicator\tindicator_type\tmeta.source\tmeta.do_notice
# EXAMPLES:
#66.32.119.38\tIntel::ADDR\tTest Address\tT
#www.honeynet.org\tIntel::DOMAIN\tTest Domain\tT
#4285358dd748ef74cb8161108e11cb73\tIntel::FILE_HASH\tTest MD5\tT
"""
USAGE_DESCRIPTION= \
"""
 
{1}NAME{0}
    iocpuller - pulls ioc data from RT and places it into an intel file.

{1}DESCRIPTION{0}
    {2}{1}NOTE: THIS SCRIPT MUST BE RUN AS ROOT.{0}

    Pulls ioc data from RT and places it into an intel file. The fields that 
    are pulled are:
      - ioc.domain
      - ioc.attackerip
      - ioc.filehash

    The domains are run through a top website list and a whitelist. If there 
    are any matches, they are not added to the intel file. You may also edit a 
    whitelist to remove indicators from the intel file.

{1}FUNCTIONS{0}
    {1}pull{0} {2}INTEL_FILE{0} {2}WEBSITES_FILE{0}
        Pull ioc data from RT while removing any top websites included in the
        top websites file and stores it in the intel file.
    {1}whitelist{0}
        Manage the whitelist file. Creates a new whitelist if there isnt one.

{1}OPTIONS{0}
    {1}-h, --help{0}
        Display the manual page.
    {1}-v, --version{0}
        Display the current version.
 
""".format(color.END, color.BOLD, color.UNDERLINE, VERSION)
WHITELIST_LOCATION = "/usr/local/bin/iocwhitelist.txt"

# intel.dat options
INDICATOR_TYPE_DOMAIN = "DOMAIN"
INDICATOR_TYPE_FILE_HASH = "FILE_HASH"
INDICATOR_TYPE_IP = "ADDR"
META_DO_NOTICE = "T"
META_SOURCE = "RT_ID: "

# RT options
USER = "user"
PASSWD = "pass"
MIN_TICKET_NUM = "0"

# -----------------------------------------------------------------------------
# Functions

# Parses arguments from the command line. Takes in intel file and top website 
# file locations so it can run mostly anywhere.
def parseArguments():
	parser = argparse.ArgumentParser(description=USAGE_DESCRIPTION, formatter_class=argparse.RawTextHelpFormatter, add_help=False)
	parser.add_argument("-v", "--version", action='version', version='%(prog)s ' + VERSION)
	parser.add_argument("-h", "--help", action='version', version=USAGE_DESCRIPTION) # THIS IS A HACK. NO TOUCHIE THANK YOU.
	subparsers = parser.add_subparsers(dest='cmd')

	# pull command
	parser_pull = subparsers.add_parser('pull')
	parser_pull.add_argument('intel', metavar="<intel_file>")
	parser_pull.add_argument('top_website', metavar="<top_websites_file>")
	# whitelist command
	parser_whitelist = subparsers.add_parser('whitelist')

	args = parser.parse_args()
	return args

# Makes a POST to RT with a field and puts the result in an array of strings 
# that have their ticket and values
# field (string) = "CF.{ioc.domain}", "CF.{ioc.attackerip}", "CF.{ioc.filehash}"
def pullListByField(field):

	# POST to get a list of all things based on a field. ex: CF.{ioc.domain}
	query = "'" + field + "'IS NOT NULL AND id > " + MIN_TICKET_NUM + " AND Status != 'rejected' AND Status != 'abandoned'"
	url = "https://12.34.56.78/REST/1.0/search/ticket?query=" + query + "&format=s&fields=" + field
	postResult = requests.post(url, {'user': USER, 'pass': PASSWD}, verify=False)
	postResultArray = postResult.text.splitlines()

	# remove first three lines and last two (response msg and empty lines)
	del postResultArray[0:3]
	del postResultArray[-1]
	del postResultArray[-1]

	return postResultArray

# Parses the values of a post result array. Makes an array of arrays that contain
# tickets and their values.
# Takes in a post result (array) created by pullListByField()
# return example: [[4044, "www.google.com"], [4045, "www.asdf.com"]]
def parseValues(postResult):
	# split the values from their ticket ids
	idValueArray = []
	for line in postResult:
		id = line.split("\t")[0]
		values = line.split("\t")[1]
		# split space delimited values
		if values.find(" ") != -1:
			valueArray = values.split(" ")
			for value in valueArray:
				idValueArray.append([id, value])
		# split comma delimited values
		elif values.find(",") != -1:
			valueArray = values.split(",")
			for value in valueArray:
				idValueArray.append([id, value])
		# add any other exception (single values)
		else:
			idValueArray.append([id, values])

	return idValueArray

# Removes duplicate values from a list while maintaining their id numbers
def removeDuplicates(idValueArray):
	uniqueValues = []
	uniqueIDValueArray = []
	for segment in idValueArray:
		value = segment[1]
		# check if the value is unique (not seen before)
		if value not in uniqueValues:
			uniqueValues.append(value)
			uniqueIDValueArray.append(segment)
	return uniqueIDValueArray

# checks if a value is in a whitelist
def isInWhitelist(value):
	for indicator in whitelist:
		if indicator == value:
			return True
	return False

def clearTerminal():
	print "\033c"

# returns an array of unique domains and their ids
def getDomains():

	# make the set unique, filter out any blank addresses, and websites in the list
	def filterDomains(domainArray):

		# checks the domain against a list using binary search
		def isInTopWebsiteList(domain):
			i = bisect.bisect_left(topWebsites, domain)
			if i != len(topWebsites) and topWebsites[i] == domain:
				return True
			else:
				return False

		# filter out any domain that has these characters:
		# '<', '>', '[', ']', '@', '/', '\', '=', '?'
		def containsIllegalChar(domain):
			if re.search('[\<\>\[\]\@\/\\\=\?]', domain) == None:
				return False
			else: 
				return True

		# filters out IPs from the domain list
		def isIP(domain):
			if re.search('[a-zA-Z]', domain) == None:
				return True
			else:
				return False

		domainArray = removeDuplicates(domainArray)
		domainArray = filter(lambda x: not containsIllegalChar(x[1]), domainArray)
		domainArray = filter(lambda x: not isIP(x[1]), domainArray)
		domainArray = filter(lambda x: len(x[1]) > 3, domainArray)
		domainArray = filter(lambda x: not isInTopWebsiteList(x[1]), domainArray)
		domainArray = filter(lambda x: not isInWhitelist(x[1]), domainArray)

		return domainArray

	# get all domains with ticket ids
	postResultArray = pullListByField("CF.{ioc.domain}")

	# get all domains into a single array
	domainArray = parseValues(postResultArray)

	# filter domains and return the array
	return filterDomains(domainArray)

# returns an array of unique file hashes and their ids
def getFileHashes():
	# get all hashes with ticket ids
	postResultArray = pullListByField("CF.{ioc.filehash}")

	# get all hashes into a single array
	hashArray = parseValues(postResultArray)

	# filter out any values that arent 32 length
	hashArray = removeDuplicates(hashArray)
	hashArray = filter(lambda x: len(x[1]) == 32, hashArray)
	hashArray = filter(lambda x: not isInWhitelist(x[1]), hashArray)

	return hashArray

# returns an array of unique IPs and their ids
def getIPS():
	# get all ips with ticket ids
	postResultArray = pullListByField("CF.{ioc.attackerip}")

	# get all IPs into a single array
	IPArray = parseValues(postResultArray)
	IPArray = filter(lambda x: not isInWhitelist(x[1]), IPArray)

	# filter out any duplicate IPs
	return removeDuplicates(IPArray)

# creates a string compatible to append to the indel.dat file
def buildIntelString(value, type, source, notice):
	return value + "\t" + "Intel::" + type + "\t" + source + "\t" + notice

# MAIN IOCPULLER FUNCTION. 
# calls all the other functions to pull ioc values from RT.
def main(intelLocation, topWebsitesLocation):
	# disable some warnings
	logging.captureWarnings(True)

	# open intel.dat and top websites file
	try:
		intelFile = open(intelLocation, "w")
		intelFile.write(INTEL_HEADER)
	except Exception as e:
		print "There was an exception opening and writing to the intel file."
		print "Exception: {}\nExiting...".format(e)
		quit()
	try:
		with open(topWebsitesLocation, 'r') as websiteFile:
			# get top 10,000 websites and sort alphabetically
			global topWebsites
			topWebsites = (websiteFile.read()).splitlines()[:10000]
			topWebsites.sort()

			print "Read top websites file: {}".format(topWebsitesLocation)
	except Exception as e:
		print "There was an exception reading the top websites file."
		print "Exception: {}\nExiting...".format(e)
		quit()

	# open whitelist file
	global whitelist
	try:
		whitelistFile = open(WHITELIST_LOCATION, "r")
		whitelist = map(lambda x: x.rstrip('\r\n'), whitelistFile.readlines())
		whitelistFile.close()
	except Exception as e:
		print "Warning: {}".format(e)
		print "Please create a whitelist using: 'iocpuller.py -w'\nExiting..."
		quit()
	
	# get all unique ioc.domain, ioc.filehash, and ioc.attackerip
	domains = getDomains()
	print "Successfully got ioc.domain list."
	IPS = getIPS()
	print "Successfully got ioc.attackerip list."
	fileHashes = getFileHashes()
	print "Successfully got ioc.filehash list."

	# write to intel file
	# first element in the array is the ticket, the second is the value
	for domain in domains:
		intelFile.write(buildIntelString(domain[1], INDICATOR_TYPE_DOMAIN, \
	                  META_SOURCE + domain[0], META_DO_NOTICE) + "\n")
	for IP in IPS:
		intelFile.write(buildIntelString(IP[1], INDICATOR_TYPE_IP, \
	                  META_SOURCE + IP[0], META_DO_NOTICE) + "\n") 
	for filehash in fileHashes:
		intelFile.write(buildIntelString(filehash[1], INDICATOR_TYPE_FILE_HASH, \
	                  META_SOURCE + filehash[0], META_DO_NOTICE) + "\n")

	print "Created intel file at location: {}".format(intelLocation)

	# close files
	intelFile.close()

# Provides functionality to update a whitelist for the intel file
def manageWhitelist():

	def printWhitelist():
		print "Total whitelisted indicators: [{}]".format(len(whitelist))
		for idx, line in enumerate(whitelist):
			print "{}) {}".format(idx,line)
		print

	# clear the terminal
	clearTerminal()

	# Menu for manipulating the whitelist file
	menu = {}
	menu['1'] = "Add indicator to whitelist."
	menu['2'] = "Delete indicator from whitelist."
	menu['3'] = "Edit an indicator."
	menu['4'] = "Print whitelist."
	menu['5'] = "Save whitelist to file."
	menu['6'] = "Clear temporary whitelist."
	menu['7'] = "Exit."

	# try opening the whitelist file
	try:
		whitelistFile = open(WHITELIST_LOCATION, "r")
		whitelist = map(lambda x: x.rstrip('\r\n'), whitelistFile.readlines())
		whitelistFile.close()
		print "Successfully opened whitelist file at: {}\n".format(WHITELIST_LOCATION)

	# prompt to create the whitelist file if it doesnt exist
	except Exception as e:
		whitelistFile = open(WHITELIST_LOCATION, "w")
		whitelistFile.close()
		whitelist = []
		print "Created new whitelist file at: {}\n".format(WHITELIST_LOCATION)
	

	# Whitelist manager loop.
	# Instead of updating the file after each change, a temporary whitelist is
	# stored in an array and manipulated. Only saved changes will be pushed to 
	# the whitelist file.
	while True: 
		# Get the options
		options = menu.keys()
		options.sort()
		whitelist.sort() # sort the whitelist for better lookups

		# print menu
		for entry in options: 
			print entry + ") " + menu[entry]
		print("-------------------------------------")

		# get input
		selection = raw_input("Selection: ") 

		# add indicator to whitelist
		if selection == '1': 
			clearTerminal()
			printWhitelist()

			enteredExit = False
			while not enteredExit:
				print "Enter an empty string to return to menu."
				indicator = raw_input("Specify an address, ip, or filehash: ")
				if indicator != "": # if its not empty
					if indicator not in whitelist: # if the indiciator isnt already in the whitelist
						whitelist.append(indicator)
						clearTerminal()
						printWhitelist()
					else: 
						clearTerminal()
						printWhitelist()
						print "Indicator already in whitelist."
				else:
					enteredExit = True
					clearTerminal()

		# delete indicator from whitelist
		elif selection == '2': 
			clearTerminal()
			enteredExit = False

			while not enteredExit:
				# print the current whitelist
				printWhitelist()
				print "Enter an empty string to return to menu."
				# checks if the index specified is valid
				validIndex = False
				while not validIndex:
					index = raw_input("Specify the index of the indicator you want to delete: ")
					if index != "":
						try:
							del(whitelist[int(index)]) # delete the indicator if its valid
							validIndex = True
						except Exception as e:
							print "Invalid index." # redo the input
					else:
						enteredExit = True
						validIndex = True

				clearTerminal()

		# edit an indicator
		elif selection == '3':
			clearTerminal()
			enteredExit = False

			while not enteredExit:
				# print the current whitelist
				printWhitelist()
				print "Enter an empty string to return to menu."
				# checks if the index specified is valid
				validIndex = False
				while not validIndex:
					index = raw_input("Specify the index of the indicator you want to modify: ")
					if index != "":
						try:
							whitelist[int(index)] # try and access the whitelist index
							newName = raw_input("Specify the new indicator name: ")
							whitelist[int(index)] = newName
							validIndex = True
						except Exception as e:
							print "Invalid index." # redo the input
					else:
						enteredExit = True
						validIndex = True
				clearTerminal()

		# print whitelist
		elif selection == '4':
			clearTerminal()
			printWhitelist()

		# save whitelist
		elif selection == '5': 
			try:
				with open(WHITELIST_LOCATION, 'w') as whitelistFile:
					for line in whitelist:
						whitelistFile.write(line + '\n')			
				clearTerminal()
				print "Saved whitelist to: {}.\n".format(WHITELIST_LOCATION)
			except Exception as e:
				clearTerminal()
				print "Warning: {}".format(e)
				print "Please run script as root!\nExiting..."
				quit()

		# clear whitelist
		elif selection == '6': 
			whitelist = []
			clearTerminal()
			print "Cleared the whitelist.\n"

		# exit the menu without saving
		elif selection == '7':
			print "Exiting..."
			break

		else: 
			clearTerminal()
			print "Invalid option. Please select again...\n" 

# -----------------------------------------------------------------------------
# Start script

if __name__ == "__main__":
	# parse arguments
	args = parseArguments()
	# update the whitelist if the option is selected
	if args.cmd == "whitelist":
		manageWhitelist()
	# pull the ioc's if the option is selected
	elif args.cmd == "pull":
		main(args.intel, args.top_website)
	# this shouldn't ever be called but... what if?
	else:
		print "Please consult the usage page: './iocpuller.py -h'"