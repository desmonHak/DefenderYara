
rule Trojan_Win32_Vundo_GVA_MTB{
	meta:
		description = "Trojan:Win32/Vundo.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8a d4 89 15 98 19 01 01 8b c8 81 e1 ff 00 00 00 89 0d 94 19 01 01 c1 e1 08 03 ca 89 0d 90 19 01 01 c1 e8 10 a3 8c 19 01 01 33 f6 } //2
		$a_01_1 = {8a 50 01 40 80 fa 22 74 29 84 d2 74 25 0f b6 d2 f6 82 61 1c 01 01 04 74 0c ff 01 85 f6 74 06 8a 10 88 16 46 40 ff 01 85 f6 74 d5 8a 10 88 16 46 eb ce } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}