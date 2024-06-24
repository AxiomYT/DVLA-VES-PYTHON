'''
DVLA.PY 24/06/2024
Author: (Axiom), mm7owo@gmail.com
Github: https://github.com/AxiomYT

DVLA.PY exists to serve as a convenient programmatic way to access the UK's DVLA VES API

The DVLA Vehicle Enquiry Service API is a RESTful service that provides vehicle details 
of a specified vehicle. It uses the vehicle registration number as input to search and 
provide details of the vehicle. The response data is provided in JSON format.

API Keys are required and can be acquired from: 
https://register-for-ves.driver-vehicle-licensing.api.gov.uk/ 

The key itself is stored on the device, in the form of a "keyring" entry. This is 
a pip package that takes in passwords / credentials, and communicates with the
host machine in order to store this string securely. Details about the project
can be found here:
https://pypi.org/project/keyring/

The registration is validated before being compiled and sent as a HTTP request, this is
done this way in order to not waste usage of the API key. There is a rate limit, 
however the exact number is obfuscated, best not push this too far.

The response is validated and checked, then displayed in both a "Raw" JSON response,
and an easy to read summary which expands on that further.
'''
import sys
import re
import textwrap
from typing import Dict, Any
import keyring
import requests

# Please do not populate this, you will be asked for it at runtime, where it will then be
# stored in the keyring.
API_KEY = None

# The DVLA VES has support for exactly 18 unique colours,
# this is revealed unofficialy in an email sent to someone asking the big questions.
# https://web.archive.org/web/20240624021417/https://www.pistonheads.com/gassing/topic.asp?h=0&f=23&t=538750#message16
# I've archived this for posterity
valid_colours = {
	"BEIGE":     "33",
	"BLUE":      "34",
	"MAROON":    "31",
	"RED":       "31",
	"BRONZE":    "33",
	"CREAM":     "93",
	"MULTI":     "95",
	"SILVER":    "37",
	"BROWN":     "40",
	"GREEN":     "32",
	"ORANGE": 	 "33",
	"TURQUOISE": "94",
	"BLACK":     "40",
	"GOLD":      "93",
	"PURPLE":    "35",
	"WHITE":     "37",
	"GREY":      "37",
	"PINK":      "95",
	"YELLOW":    "93",
}

def get_api_key() -> str:
	'''
	In order to not store your API key in the file, we utilise the 
	project https://pypi.org/project/keyring/ . This ensures that
	your key is not leaked if this file is shared or accessed
	through any means other than via a signed-in user on the machine.

	This tool supports:
    	macOS Keychain
    	Freedesktop Secret Service
    	KDE4 & KDE5 KWallet
    	Windows Credential Locker

	And should natively pick the correct method to store your key on your device.

	'''

	# If we can find this key right away, we can exit early.
	if (api_key := keyring.get_credential("DVLA-API-KEY", "")):
		return api_key.password

	# If we can't find a key with service name "DVLA-API-KEY"
	print("Could not find API key stored in keyring...")
	temp_key = input("please enter your API key here: ").strip()
	temp_user = input("Now please enter a username to store this alongside, this is required: ")
	# keyring requires use of a username, however we have no need of that in this programme.
	# You can enter anything you like here, just remember that it's stored on device
	# under that 'username' you have picked.
	keyring.set_password("DVLA-API-KEY", temp_user, temp_key)

	# We can then test if this worked by polling for the key we just set.
	if not keyring.get_credential("DVLA-API-KEY", temp_user).password:
		raise TypeError("Could not find API key stored in keyring")

	del temp_key, temp_user
	return keyring.get_credential("DVLA-API-KEY", temp_user).password

def validate_reg(registration: Dict[str, str]) -> bool:
	''' 
	This is the first method that is called. Pass it a string containing a supposedly valid 
	UK+NI registration, and it will return a boolean True/False depending on if the
	RegEx check has passed or not.

	'''
	internal_reg = str(registration["registrationNumber"]).upper()

	# Thanks to Github User Danielrbradley for the validation RegEx
	# https://gist.github.com/danielrbradley/7567269?permalink_comment_id=3796652#gistcomment-3796652
	pattern = r"""^((?P<Current>[A-Z]{2}[0-9]{2}\s?[A-Z]{3})|
					(?P<Prefix>[A-Z][0-9]{1,3}\s?[A-Z]{3})|
					(?P<Suffix>[A-Z]{3}\s?[0-9]{1,3}[A-Z])|
					(?P<DatelessLongNumberPrefix>[0-9]{1,4}\s?[A-Z]{1,2})|
					(?P<DatelessShortNumberPrefix>[0-9]{1,3}\s?[A-Z]{1,3})|
					(?P<DatelessLongNumberSuffix>[A-Z]{1,2}\s?[0-9]{1,4})|
					(?P<DatelessShortNumberSuffix>[A-Z]{1,3}\s?[0-9]{1,3})|
					(?P<DatelessNorthernIreland>[A-Z]{1,3}\s?[0-9]{1,4})|
					(?P<DiplomaticPlate>[0-9]{3}\s?[DX]{1}\s?[0-9]{3}))$ 
				"""
	return bool(re.search(pattern, internal_reg, re.VERBOSE))

def make_request(request_payload: Dict[str, Any]) -> Dict[str, Any]:
	r'''
	Programatically makes the actual HTTP request, and contains rudimentary status code validation
	for the response. This is returned in the form of a dictionary, with key-value pairs
	pertaining to every vehicle data entry the API exposes.

	Some data is not returned / handled differently depending on the vehicle, for example:
	/------------------------------------------------------------------------------\
	|| VEHICLE             || taxStatus || motStatus             || taxDueDate    ||
	||---------------------||-----------||-----------------------||---------------||
	|| Compliant  Vehicles || "Taxed"   || "Valid"               || "YYYY-MM-DD"  ||
	|| SORNed     Vehicles || "SORN"    || "SORN"                || NULL          ||
	|| MOT Exempt Vehicles || "Taxed"   || "No results returned" || "YYYY-MM-DD"  ||
	\------------------------------------------------------------------------------/

	Wherein;
		Vehicles older than 40 years
    	Mobile cranes and Pumps
    	Road rollers, Works trucks and Digging machines
    	Agricultural machines and Mowing machines
    	Snowploughs and gritting vehicles
    	Electric vehicles
    	Steam vehicles

	are exempt from paying vehicle tax, and will have a status of "No results returned"

	'''
	url = "https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles"
	headers = {'x-api-key': API_KEY, 'Content-Type': 'application/json'}
	response = requests.request("POST", url, headers=headers, json = request_payload, timeout = 10)

	json_response = response.json()

	match response.status_code:
		case 418:
			print("I'm a teapot")
			raise SystemExit(0)
		case 404:
			print(f"No Record of Vehicle exists with Registration: {request_payload['registrationNumber']}")
			raise SystemExit(0)
		case 403:
			print(f"Unauthorised / Forbidden 403\nIs the API key correct? \nUsing key: {API_KEY}")
			raise SystemExit(0)
		case 200:
			# Success, break this case statement
			pass
		case _:
			print(f"Undefined Error {response.status_code}")
			raise SystemExit(0)

	print("\033[13mRaw Response --\033[0m")
	for key, data in json_response.items():
		print(f"{key}: \033[90m{data}\033[0m")


	return {"registrationNumber":  json_response.get("registrationNumber", None),
			"taxStatus": 		   json_response.get("taxStatus", None),
			"taxDueDate":          json_response.get("taxDueDate", None),
   			"motStatus": 		   json_response.get("motStatus", None),
			"make": 			   json_response.get("make", None),
   			"yearOfManufacture":   json_response.get("yearOfManufacture", None),
   			"engineCapacity":      json_response.get("engineCapacity", None),
   			"co2Emissions":        json_response.get("co2Emissions", None),
			"fuelType": 		   json_response.get("fuelType", None),
			"markedForExport":     json_response.get("markedForExport", None),
   			"colour": 			   json_response.get("colour", None),
   			"typeApproval": 	   json_response.get("typeApproval", None),
   			"dateOfLastV5CIssued": json_response.get("dateOfLastV5CIssued", None),
			"motExpiryDate": 	   json_response.get("motExpiryDate", None)
	}

def display_response(returned_data: Dict[str, Any]) -> None:
	'''
	This method pretty-prints all of the data we have collected, with ANSI escape sequences 
	depending on the result in each field. 
	
	This should be cross compatible with most terminal environments. And if not, will be 
	silently ignored. some colours are rendered differently depending on the interpreter.
	such as Yellow appearing as Orange on Windows Machines.

	We specifically use VGA standard 4-bit colour codes, to ensure highest possible compatibility.
	This is the last method called and is the last step needed for actually showing our response.
	'''
	terminal_green = {"Valid", "Taxed", "No results returned", "SORN"}
	terminal_red = {"Invalid", "Untaxed", "Not valid"}
	ignore = {"engineCapacity", "markedForExport", "typeApproval", "co2Emissions",
			  "dateOfLastV5CIssued", "motExpiryDate", "taxDueDate"}

	print("\n\033[13mSummary -- \033[0m")
	for element, value in returned_data.items():				# Print out most relevant stuff
		if element in ignore:									# Strip fields we don't care about
			continue

		if value in terminal_green:								# If the result is positive
			if value == "No results returned":					# ("Valid", "No results returned (Exempt)", or "SORN"ed)
				print(f"\033[92m{element}: MOT Exempt\033[0m")	# Then we print this text as Green \033[92m
			else:
				print(f"\033[92m{element}: {value}\033[0m")
		elif value in terminal_red:								# If the result is negative
			if returned_data.get("taxStatus") == "SORN":		# ("Not valid", "No MOT and *NOT* SORNed")
				print(f"\033[92m{element}: SORN\033[0m")		# Then this shall instead be Red \033[31m
			else:
				print(f"\033[31m{element}: {value}\033[0m")
		elif element == "colour":								# The DVLA only officially supports 18 unique colours
			if value in valid_colours:							# We can therefore support hard-coded colours in the terminal
				print(f"\033[{valid_colours[value]}m{element}: {value}\033[0m\n")
			else:
				print(f"\033[33m{element}: {value}\033[0m")
		else:
			print(f"\033[0m{element}:  \033[90m{value}\033[0m")

def main(internal_payload: Dict[str, str]) -> None:
	''' 
	Pass this function a payload in the form of a tuple like so {"registrationNumber": sys.argv[reg]}
	for example, payload = {"registrationNumber": "AB51ABC"}

	This is the main function that handles all of the setting and getting.
	'''
	try:
		if not validate_reg(internal_payload):
			raise ValueError(textwrap.dedent(f"""\
				{internal_payload['registrationNumber']} is not a valid UK Vehicle registration.

				If this seems incorrect, please raise a complaint on the GitHub page.
				"""))
	except ValueError as invalid_registration:
		print(invalid_registration)
		sys.exit(1)

	returned_data = make_request(internal_payload)

	display_response(returned_data)


if __name__ == '__main__':
	API_KEY = get_api_key()

	if len(sys.argv) < 2:		# If the user doesn't supply any registrations to check
		print("Pass this script a valid UK registration plate and it will return details.")
		sys.exit(1)

	# We support as many sequential requests as python will accept, oh and your API key of course.
	for reg in range (1, len(sys.argv)):
		try:
			print(f"\033[34m\n---- Registration {sys.argv[reg]} ----\033[0m")
			payload = {"registrationNumber": sys.argv[reg]}
			main(payload)
		except IndexError:
			print("Pass this script a valid UK registration plate and it will return details.")
			sys.exit()
