
rule Trojan_Win32_XWorm_MCN_MTB{
	meta:
		description = "Trojan:Win32/XWorm.MCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 53 71 75 69 7a 50 61 82 9a 00 00 00 10 08 00 00 9c 00 00 00 f6 07 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 65 68 5f 66 72 61 6d 04 00 00 00 00 b0 08 00 00 02 00 00 00 92 08 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 70 64 61 74 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}