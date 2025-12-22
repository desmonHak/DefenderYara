
rule Trojan_Win64_DllHijack_HR_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b e0 65 48 8b 04 25 60 00 00 00 4c 8b 78 18 49 83 c7 20 4d 8b 37 4d 3b f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}