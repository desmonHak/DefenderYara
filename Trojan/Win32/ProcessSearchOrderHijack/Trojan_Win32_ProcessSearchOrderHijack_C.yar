
rule Trojan_Win32_ProcessSearchOrderHijack_C{
	meta:
		description = "Trojan:Win32/ProcessSearchOrderHijack.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 00 68 00 6f 00 61 00 6d 00 69 00 } //1 whoami
		$a_00_1 = {68 00 65 00 6c 00 70 00 } //1 help
		$a_00_2 = {69 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 } //1 ipconfig
		$a_01_3 = {2a 2a 2a 5f 5f 63 38 61 31 30 62 34 63 2d 30 32 39 38 2d 34 61 32 31 2d 39 64 63 31 2d 34 61 38 34 33 61 33 38 65 34 62 35 5f 5f 2a 2a 2a } //-10 ***__c8a10b4c-0298-4a21-9dc1-4a843a38e4b5__***
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*-10) >=1
 
}