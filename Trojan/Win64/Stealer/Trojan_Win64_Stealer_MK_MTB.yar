
rule Trojan_Win64_Stealer_MK_MTB{
	meta:
		description = "Trojan:Win64/Stealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 71 01 0f b6 3c 38 48 39 d6 ?? ?? 48 89 44 24 58 40 88 7c 24 43 48 89 4c 24 78 } //15
		$a_03_1 = {48 ff c3 0f 1f 00 48 83 fb 0a ?? ?? 48 8d 34 0a 48 01 de 48 83 fe ff } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}