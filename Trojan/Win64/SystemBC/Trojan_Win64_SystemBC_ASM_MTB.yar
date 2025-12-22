
rule Trojan_Win64_SystemBC_ASM_MTB{
	meta:
		description = "Trojan:Win64/SystemBC.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 07 32 04 31 aa 48 ff 4d 28 48 ff c1 48 3b 4d 18 75 03 48 33 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}