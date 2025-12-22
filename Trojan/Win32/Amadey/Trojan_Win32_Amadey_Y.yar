
rule Trojan_Win32_Amadey_Y{
	meta:
		description = "Trojan:Win32/Amadey.Y,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 6f 73 5f 62 61 73 65 3a 3a 65 6f 66 62 69 74 20 73 65 74 00 00 00 00 90 04 20 06 30 2d 39 61 2d 66 00 00 00 00 90 04 20 06 30 2d 39 61 2d 66 00 00 00 00 90 04 06 06 30 2d 39 61 2d 66 00 00 90 04 20 06 30 2d 39 61 2d 66 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}