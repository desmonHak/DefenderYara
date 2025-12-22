
rule Trojan_Win32_DiskCoder_Z_MTB{
	meta:
		description = "Trojan:Win32/DiskCoder.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c7 c1 c0 07 44 33 c8 8b 45 7f 41 03 c1 c1 c0 09 44 33 f0 43 8d 04 0e c1 c0 0d 33 f8 89 3c 24 41 8d 04 3e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}