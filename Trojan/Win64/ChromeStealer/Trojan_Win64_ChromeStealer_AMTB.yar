
rule Trojan_Win64_ChromeStealer_AMTB{
	meta:
		description = "Trojan:Win64/ChromeStealer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {25 73 5c 63 68 72 6f 6d 65 5f 6d 61 73 74 65 72 5f 6b 65 79 2e 62 69 6e } //%s\chrome_master_key.bin  1
		$a_80_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 } //taskkill /F /IM chrome.exe  1
		$a_80_2 = {25 73 5c 63 68 72 6f 6d 65 5f 70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //%s\chrome_passwords.txt  1
		$a_80_3 = {5b 25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 25 73 } //[%04d-%02d-%02d %02d:%02d:%02d] %s  1
		$a_80_4 = {53 65 74 74 69 6e 67 20 75 70 20 43 4f 4d 20 68 69 6a 61 63 6b } //Setting up COM hijack  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}