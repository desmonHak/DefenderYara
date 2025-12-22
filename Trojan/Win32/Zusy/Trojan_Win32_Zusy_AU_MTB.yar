
rule Trojan_Win32_Zusy_AU_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 10 04 01 0f 28 ca 0f 57 c2 0f 11 04 01 0f 10 84 05 40 f5 ff ff 0f 57 c2 0f 11 84 05 40 f5 ff ff 0f 10 04 02 0f 57 c8 0f 11 0c 02 0f 10 04 06 0f 57 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}