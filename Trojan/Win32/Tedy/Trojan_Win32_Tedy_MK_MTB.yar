
rule Trojan_Win32_Tedy_MK_MTB{
	meta:
		description = "Trojan:Win32/Tedy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 0c 07 42 0f b6 44 85 b8 48 c1 e1 ?? 48 03 c1 46 32 8c 20 90 90 89 04 00 42 0f b6 44 85 b9 48 03 c1 } //15
		$a_01_1 = {48 8d 49 04 42 0f b6 84 20 90 88 04 00 88 41 fa 0f b6 41 fb 42 0f b6 84 20 90 88 04 00 88 41 fb 0f b6 41 fc } //10
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}