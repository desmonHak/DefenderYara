
rule Trojan_Win32_Reconyc_NC_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 d2 75 0c c7 45 fc 1b 00 00 00 e9 b9 03 00 00 8b 45 08 50 e8 e2 c3 ff ff 83 c4 04 8b 4d 08 0f b6 91 d3 02 00 00 85 d2 74 14 } //2
		$a_01_1 = {0f 84 a5 00 00 00 8b 4d f0 c6 41 40 01 8b 55 f0 52 8b 45 f8 50 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}