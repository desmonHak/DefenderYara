
rule Trojan_BAT_Stealer_HAB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.HAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 08 00 00 "
		
	strings :
		$a_81_0 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //10 Google\Chrome\User Data\Default\Login Data
		$a_81_1 = {43 68 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //10 Chromium\User Data\Default\Login Data
		$a_81_2 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //10 Microsoft\Edge\User Data\Default\Login Data
		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4d 65 73 73 61 67 69 6e 67 20 53 75 62 73 79 73 74 65 6d 5c 50 72 6f 66 69 6c 65 73 5c } //5 Software\Microsoft\Windows Messaging Subsystem\Profiles\
		$a_81_4 = {5c 4f 75 74 6c 6f 6f 6b 5c 50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b 5c } //5 \Outlook\Profiles\Outlook\
		$a_81_5 = {43 6c 61 73 73 65 73 5c 46 6f 78 6d 61 69 6c } //5 Classes\Foxmail
		$a_81_6 = {46 69 6c 65 5a 69 6c 6c 61 5c 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //15 FileZilla\recentservers.xml
		$a_81_7 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //10 PK11SDR_Decrypt
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*5+(#a_81_4  & 1)*5+(#a_81_5  & 1)*5+(#a_81_6  & 1)*15+(#a_81_7  & 1)*10) >=70
 
}