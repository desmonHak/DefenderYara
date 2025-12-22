
rule Trojan_Linux_SAgnt_AB_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.AB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 7f 02 3c ff ff 42 34 2b 10 a2 00 11 00 40 14 25 90 a0 00 7c 80 99 8f 09 f8 20 03 00 00 00 00 0c 00 03 24 } //1
		$a_01_1 = {00 00 65 80 05 00 a4 54 01 00 60 a0 05 00 40 10 ff ff 42 24 fa ff 00 10 21 18 02 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}