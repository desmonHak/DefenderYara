
rule Trojan_Win64_BumbleBee_CA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 04 01 00 00 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 33 db 48 8d 3d ?? ?? ?? ?? 48 8b 17 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 85 c0 74 0f ff c3 48 83 c7 ?? 83 fb 1b 72 } //3
		$a_03_1 = {2b c1 66 89 84 24 e8 75 00 00 e8 ?? ?? ?? ?? 85 c0 74 ?? 48 c7 84 24 40 28 00 00 00 00 00 00 48 8b 84 24 40 28 00 00 c6 00 ff 33 c9 ff 15 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=3
 
}