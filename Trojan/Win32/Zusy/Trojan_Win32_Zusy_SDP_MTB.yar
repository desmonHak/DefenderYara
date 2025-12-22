
rule Trojan_Win32_Zusy_SDP_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {f4 b6 44 00 5e 00 05 ?? ?? ?? ?? 31 00 00 8d } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}