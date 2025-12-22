
rule Trojan_Win32_Fragtor_MK_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 8e 01 00 00 2b c6 8d 7e 01 0f af c7 c1 e0 04 03 d8 ff 85 b0 f8 ff ff 8b 85 a0 f8 ff ff } //15
		$a_01_1 = {8a 8d a7 f8 ff ff 8b 95 c0 f8 ff ff 88 0c 10 8b 8d 90 f8 ff ff 8a 54 08 01 8b 8d c0 f8 ff ff 88 54 08 01 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}