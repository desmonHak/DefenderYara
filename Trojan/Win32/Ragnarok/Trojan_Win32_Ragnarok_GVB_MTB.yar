
rule Trojan_Win32_Ragnarok_GVB_MTB{
	meta:
		description = "Trojan:Win32/Ragnarok.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f0 55 8d 52 01 66 89 06 8d b5 58 ff ff ff 0f b7 0c 56 8d 34 56 8b c1 66 85 c9 75 e3 } //2
		$a_01_1 = {2e 72 61 67 6e 61 72 6f 6b } //1 .ragnarok
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}