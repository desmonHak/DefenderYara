
rule Trojan_Win32_SmokeLoader_EA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.EA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_00_0 = {2f 00 63 00 20 00 63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 20 00 90 00 02 00 10 00 2e 00 70 00 64 00 66 00 20 00 90 00 02 00 10 00 2e 00 62 00 61 00 74 00 20 00 26 00 20 00 90 00 02 00 10 00 2e 00 62 00 61 00 74 00 90 00 00 00 } //4
	condition:
		((#a_00_0  & 1)*4) >=4
 
}