
rule Trojan_Win64_PurelogStealer_HR_MTB{
	meta:
		description = "Trojan:Win64/PurelogStealer.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 01 48 b8 0b d7 a3 70 3d 0a d7 a3 48 89 d6 48 f7 ea 48 8d 04 16 48 c1 f8 06 48 89 f2 48 c1 fe 3f 48 29 f0 48 6b c0 64 48 29 c2 48 89 51 08 48 b8 96 b2 0c 71 ac 8b db 68 48 f7 ef 48 c1 fa 0c 48 29 da 48 b8 0b d7 a3 70 3d 0a d7 a3 48 89 d3 48 f7 ea 48 8d 04 1a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}