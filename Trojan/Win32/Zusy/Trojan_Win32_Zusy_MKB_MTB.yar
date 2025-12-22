
rule Trojan_Win32_Zusy_MKB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 55 fb 0f b6 85 6e ff ff ff 03 d0 0f b7 8d 30 ff ff ff 33 d1 0f b7 85 44 ff ff ff 03 c2 66 89 85 44 ff ff ff } //15
		$a_01_1 = {0f b7 85 78 ff ff ff 2b d0 03 55 c8 33 55 c8 88 55 f9 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}