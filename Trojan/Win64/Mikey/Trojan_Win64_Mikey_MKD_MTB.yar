
rule Trojan_Win64_Mikey_MKD_MTB{
	meta:
		description = "Trojan:Win64/Mikey.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 03 83 c9 ff 41 ff c9 41 2b c2 41 2b ca 48 8d 5b 04 3b c1 } //15
		$a_01_1 = {8b 16 44 8b 0b 41 ff cb 03 d0 48 8d 5b 04 48 8d 76 04 4c 0f af cd 4d 8b d1 41 89 10 49 c1 fa 20 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}