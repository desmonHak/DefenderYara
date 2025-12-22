
rule Trojan_Win32_StealC_SI_MTB{
	meta:
		description = "Trojan:Win32/StealC.SI!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 30 e3 48 8d 36 48 83 c0 01 48 39 c8 } //1
		$a_01_1 = {f6 22 88 02 41 54 41 5c 48 83 c2 01 48 39 ca } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}