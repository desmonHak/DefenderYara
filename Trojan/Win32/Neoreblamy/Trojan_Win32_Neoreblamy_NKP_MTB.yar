
rule Trojan_Win32_Neoreblamy_NKP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 56 ff 2b c1 03 d0 79 12 83 c8 ff 2b c2 81 c2 00 01 00 00 25 00 ff ff ff 03 d0 } //1
		$a_03_1 = {6a 04 5f 83 c1 02 eb 33 0f b6 84 0d ?? ?? ff ff 8d 57 ff 2b c1 03 d0 } //2
		$a_03_2 = {33 c0 8d 8d ?? ?? ff ff 40 33 db 53 50 88 45 fc } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=5
 
}