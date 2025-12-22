
rule Trojan_Win64_Vidar_YNE_MTB{
	meta:
		description = "Trojan:Win64/Vidar.YNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 46 46 77 ff b8 77 ef 45 56 81 f9 46 46 77 ff 74 12 81 f9 77 ef 45 56 } //10
		$a_03_1 = {81 fa 9e 74 [0-04] 60 7f 14 81 fa f4 09 48 e3 74 [0-04] 81 fa bf e5 5b 2b 75 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}