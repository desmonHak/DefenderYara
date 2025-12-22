
rule Trojan_Win32_StealC_VZY_MTB{
	meta:
		description = "Trojan:Win32/StealC.VZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 3d 00 01 00 00 74 ?? 39 14 85 ?? ?? ?? ?? 75 ?? 88 04 0b 83 c1 01 81 f9 d2 49 06 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}