
rule Trojan_Win64_Vidar_AHB_MTB{
	meta:
		description = "Trojan:Win64/Vidar.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 84 24 18 01 00 00 48 89 c6 48 83 e0 fc 48 89 f7 48 29 c6 48 83 fe ?? 7f } //30
		$a_03_1 = {48 89 d6 48 f7 eb 48 8d 3c 13 48 c1 ff ?? 48 29 cf 48 8d 3c bf 48 29 fb 48 39 de 7c ab } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}