
rule Trojan_Win64_DCRat_GVC_MTB{
	meta:
		description = "Trojan:Win64/DCRat.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b0 06 bd c2 ef d9 fe 50 21 51 fa 29 c9 4c 85 15 00 19 1b 04 3d d9 48 c7 7d 30 64 e8 47 7a 6c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}