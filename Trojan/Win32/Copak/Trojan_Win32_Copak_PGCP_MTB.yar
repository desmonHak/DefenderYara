
rule Trojan_Win32_Copak_PGCP_MTB{
	meta:
		description = "Trojan:Win32/Copak.PGCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {a0 86 45 00 c3 [0-1f] cc ?? 47 00 [0-1f] e8 ?? 00 00 00 [0-1a] 31 [0-0f] 81 ?? 02 00 00 00 [0-0f] 39 ?? 7c } //5
		$a_03_1 = {a0 96 45 00 c3 [0-1f] cc ?? 47 00 [0-1f] e8 ?? 00 00 00 [0-1a] 31 [0-0f] 81 ?? 02 00 00 00 [0-0f] 39 ?? 7c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}