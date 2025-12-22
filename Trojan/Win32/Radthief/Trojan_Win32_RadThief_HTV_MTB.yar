
rule Trojan_Win32_RadThief_HTV_MTB{
	meta:
		description = "Trojan:Win32/RadThief.HTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 31 46 8b 45 ?? 89 75 e0 8b 08 8b 40 04 2b c1 89 4d e4 3b f0 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}