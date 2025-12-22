
rule Trojan_Win32_Dostilbot_Z_MTB{
	meta:
		description = "Trojan:Win32/Dostilbot.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 cb 0b 41 21 c5 49 83 c2 04 c1 e1 18 c1 e2 10 09 d1 41 0f b6 52 ff 09 d1 41 0f b6 52 fe c1 e2 08 09 d1 89 f2 c1 ca 06 41 89 4a 6c 31 da 89 f3 c1 c3 07 31 da 89 f3 f7 d3 44 21 c3 44 31 eb 01 da 03 57 fc 44 89 db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}