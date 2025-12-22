
rule Trojan_Win32_XWorm_MCM_MTB{
	meta:
		description = "Trojan:Win32/XWorm.MCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 42 35 21 f0 1f 2a [0-30] f8 1a 40 00 10 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 02 00 01 00 e9 00 00 00 a0 13 40 00 24 15 40 00 20 11 40 00 78 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}