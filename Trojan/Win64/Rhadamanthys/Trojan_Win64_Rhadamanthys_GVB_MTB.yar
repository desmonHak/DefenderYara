
rule Trojan_Win64_Rhadamanthys_GVB_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 32 b1 4d 8d 24 24 48 83 c2 01 4c 39 c2 75 f0 } //2
		$a_01_1 = {4d 8d 6d 00 88 08 48 83 c0 01 4c 39 c0 75 e6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}