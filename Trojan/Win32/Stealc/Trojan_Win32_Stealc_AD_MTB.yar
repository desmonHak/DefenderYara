
rule Trojan_Win32_Stealc_AD_MTB{
	meta:
		description = "Trojan:Win32/Stealc.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 06 84 c0 ?? ?? 32 45 ff 8b 5d ?? 2a c1 fe c8 88 04 32 41 46 3b cf } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}