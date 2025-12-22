
rule Trojan_Win32_Sysdupate_GVA_MTB{
	meta:
		description = "Trojan:Win32/Sysdupate.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 7d f4 68 04 01 00 00 8d 85 f0 fe ff ff 50 a5 66 a5 a4 33 f6 56 } //1
		$a_01_1 = {8b f8 0f b7 06 8b cf c1 c9 08 46 03 c8 33 f9 80 3e 00 75 ee } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}