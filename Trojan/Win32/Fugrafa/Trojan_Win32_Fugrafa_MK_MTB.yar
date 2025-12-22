
rule Trojan_Win32_Fugrafa_MK_MTB{
	meta:
		description = "Trojan:Win32/Fugrafa.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 85 70 f7 ff ff 33 d2 c6 04 01 ?? 90 90 0f b7 ?? ?? ?? ?? ?? 8d 52 ?? 66 89 8c 15 7e f9 ff ff 66 85 c9 } //15
		$a_01_1 = {8b 7d b0 03 f9 89 7d d8 8b 17 8b f2 8b 5f cc 8b ca c1 c9 11 c1 ea 0a c1 ce 13 33 f1 8b cb c1 c9 07 33 f2 8b d3 c1 ca 12 33 d1 8b cb c1 e9 03 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}