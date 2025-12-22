
rule Trojan_BAT_Lazy_LMO_MTB{
	meta:
		description = "Trojan:BAT/Lazy.LMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 38 33 fa ff ff 20 1e 95 28 fd 13 08 11 17 20 41 c4 57 c4 5a 20 26 20 41 02 61 38 19 fa ff ff 11 15 1f 10 2f 08 20 7b 5c f4 93 25 2b 06 20 d5 02 c8 fe 25 } //20
		$a_01_1 = {2b 06 20 68 6a c4 fb 25 26 11 17 20 0a 9c 7f c5 5a 61 38 9d fa ff ff 11 07 25 1a 58 13 07 4b 11 07 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}