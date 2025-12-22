
rule Trojan_Win32_Ragnarok_GVA_MTB{
	meta:
		description = "Trojan:Win32/Ragnarok.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c7 33 d2 f7 75 fc 83 7b 14 07 8d 04 51 8b cb 76 02 8b 0b 8b 55 f8 66 8b 00 66 33 02 66 89 04 79 47 3b 7e 10 72 b6 } //2
		$a_01_1 = {2e 72 61 67 6e 61 72 6f 6b } //1 .ragnarok
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}