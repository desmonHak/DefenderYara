
rule Trojan_Win64_CryptInject_RH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.RH!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 00 6e 00 65 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 76 00 69 00 73 00 61 00 2e 00 63 00 6f 00 6d 00 } //1 oneglobalvisa.com
		$a_01_1 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //1 chrome.exe
		$a_01_2 = {61 00 70 00 69 00 2f 00 68 00 6f 00 73 00 70 00 69 00 74 00 61 00 6c 00 2f 00 64 00 61 00 74 00 61 00 2f 00 } //1 api/hospital/data/
		$a_01_3 = {5c 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //1 \Network\Cookies
		$a_01_4 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 } //1 \appdata\local
		$a_01_5 = {63 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 65 00 6c 00 66 00 2e 00 64 00 6c 00 6c 00 } //1 chrome_elf.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}