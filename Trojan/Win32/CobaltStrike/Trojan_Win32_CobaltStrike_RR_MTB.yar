
rule Trojan_Win32_CobaltStrike_RR_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 30 31 2e 34 32 2e 31 37 35 2e 38 39 } //1 101.42.175.89
		$a_01_1 = {76 77 78 79 7a 31 32 33 34 35 36 37 38 39 30 31 31 31 31 31 31 31 31 } //1 vwxyz123456789011111111
		$a_01_2 = {68 6c 6c 6f 63 68 75 61 6c 41 68 56 69 72 74 54 } //1 hllochualAhVirtT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}