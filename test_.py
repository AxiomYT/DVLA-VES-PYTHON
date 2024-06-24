'''
Test Cases for DVLA.py
'''

from dvla import validate_reg

reg_list_valid = [
    "NG04DNJ", "WF61ZZH", "AB51ABC", "A51ABC", "A123ABC", "A12ABC", "A1ABC", 
    "123ABC", "ABC123A", "ABC12A", "ABC1A", "ABC123", "1ABC", "ABC1", "1234A", 
    "A1234", "1234AB", "AB1234", "123ABC", "ABC123", "ABC123", 
    "ABC1234", "101D234", "123X456"
]

reg_list_invalid = [
    "ABC54ABC", "AB5ABC", "AB543ABC", "AB54AB", "AB54ABCD", "AB1ABC", "AABC", 
    "A1234ABC", "A1AB", "A1ABCD", "AB1A", "AB123A", "ABCD1A", "ABCD123A", 
    "ABCA", "ABC1234A", "ABC1AB", "ABC", "12345A", "A12345", "1", "123", 
    "1234", "1ABCD", "ABCD1", "ABCD123", "ABCD123", "ABC12345", "123A456", 
    "1234D567", "123X4567", "1234ABC"
]

def test_working():
	''' Top List '''
	for reg in reg_list_valid:
		assert validate_reg({"registrationNumber": reg}) is True

def test_fail():
	''' Bottom List '''
	for reg in reg_list_invalid:
		assert validate_reg({"registrationNumber": reg}) is False
