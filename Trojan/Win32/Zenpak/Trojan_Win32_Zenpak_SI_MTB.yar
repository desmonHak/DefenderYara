
rule Trojan_Win32_Zenpak_SI_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 e8 8b 5d d0 8a 1c 1e 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d0 88 1c 31 8b 4d f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}