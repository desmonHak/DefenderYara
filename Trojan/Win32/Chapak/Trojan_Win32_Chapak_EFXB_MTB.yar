
rule Trojan_Win32_Chapak_EFXB_MTB{
	meta:
		description = "Trojan:Win32/Chapak.EFXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 4d fc c1 e0 04 03 45 f8 33 c8 8d 04 3b 33 c8 8d 9b } //2
		$a_01_1 = {8a 0c 0a 88 0c 02 42 8b 85 44 f7 ff ff 8b 8d 3c f7 ff ff 3b d0 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}