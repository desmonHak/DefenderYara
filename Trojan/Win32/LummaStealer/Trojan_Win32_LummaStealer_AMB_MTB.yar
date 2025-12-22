
rule Trojan_Win32_LummaStealer_AMB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 e0 30 c1 08 cb 89 d8 80 e3 95 f6 d0 24 6a 08 c3 89 d0 80 f3 95 20 d8 30 d3 ba ?? ?? ?? ?? 08 c3 88 1c 37 8b 45 ?? 40 89 45 ?? 81 fa } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}