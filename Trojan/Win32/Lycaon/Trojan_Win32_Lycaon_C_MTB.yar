
rule Trojan_Win32_Lycaon_C_MTB{
	meta:
		description = "Trojan:Win32/Lycaon.C!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b4 21 80 f8 3c c0 10 00 8b 8d ac fe ff ff 8b 95 08 fa ff ff 8b 85 64 ff ff ff 03 04 8a 89 85 a8 fe ff ff 8b 8d ac fe ff ff 8b 95 04 fa ff ff 0f b7 04 4a 8b 8d 00 fa ff ff 8b 95 64 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}