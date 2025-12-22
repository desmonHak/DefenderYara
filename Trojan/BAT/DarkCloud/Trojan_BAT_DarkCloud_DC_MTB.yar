
rule Trojan_BAT_DarkCloud_DC_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_81_0 = {3d 44 41 52 4b 43 4c 4f 55 44 3d } //10 =DARKCLOUD=
		$a_81_1 = {5c 65 4d 20 43 6c 69 65 6e 74 5c 6d 61 69 6e 2e 64 61 74 } //10 \eM Client\main.dat
		$a_81_2 = {43 61 72 64 20 4e 75 6d 62 65 72 3a 20 } //1 Card Number: 
		$a_81_3 = {43 61 72 64 20 54 79 70 65 } //1 Card Type
		$a_81_4 = {4c 6f 67 69 6e 20 44 61 74 61 } //1 Login Data
		$a_81_5 = {55 73 65 72 20 44 61 74 61 } //1 User Data
		$a_81_6 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 logins.json
		$a_81_7 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //1 api.telegram.org/bot
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=26
 
}