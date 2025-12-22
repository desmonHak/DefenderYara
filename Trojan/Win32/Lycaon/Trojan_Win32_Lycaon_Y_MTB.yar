
rule Trojan_Win32_Lycaon_Y_MTB{
	meta:
		description = "Trojan:Win32/Lycaon.Y!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2d 2b c8 8b 95 c4 fd ff ff 81 c2 8f 79 1a 1b 33 d1 0f af 95 c8 fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}