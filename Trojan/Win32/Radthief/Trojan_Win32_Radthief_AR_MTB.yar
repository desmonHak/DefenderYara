
rule Trojan_Win32_Radthief_AR_MTB{
	meta:
		description = "Trojan:Win32/Radthief.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 1e 33 d0 69 c2 ?? ?? ?? ?? 03 c1 89 44 8c 04 41 81 f9 } //10
		$a_01_1 = {8b 45 c8 8b 4d cc 89 45 c0 89 4d c4 ff d7 2b 45 d0 1b 55 d4 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}
rule Trojan_Win32_Radthief_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Radthief.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 f2 88 54 04 ?? 48 ff c0 48 83 f8 ?? ?? ?? 48 89 c2 48 83 e2 f0 48 89 c6 48 29 d6 } //20
		$a_03_1 = {44 31 cf 42 88 bc 04 ?? ?? ?? ?? 49 8d 48 01 48 83 f9 ?? 7d 18 48 89 cf 48 83 e1 } //15
		$a_01_2 = {48 39 c8 7e 19 48 89 c6 48 29 ce 48 8d 7e ff 44 0f b6 04 0a 48 39 f8 } //5
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*15+(#a_01_2  & 1)*5) >=40
 
}