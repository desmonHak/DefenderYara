
rule Trojan_Win32_Copak_PGCO_MTB{
	meta:
		description = "Trojan:Win32/Copak.PGCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {a0 56 46 00 c3 [0-1a] 08 4a 48 00 [0-1a] e8 ?? 00 00 00 [0-1a] 31 [0-1a] 81 ?? 02 00 00 00 [0-0f] 39 ?? 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Copak_PGCO_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.PGCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {a0 56 46 00 c3 [0-0f] 08 4a 48 00 [0-0a] e8 ?? 00 00 00 [0-0f] 31 [0-08] 81 ?? 02 00 00 00 [0-0f] 39 ?? 7c } //5
		$a_03_1 = {a0 96 45 00 c3 [0-1a] cc 46 47 00 [0-1a] e8 ?? 00 00 00 [0-1f] 31 [0-1a] 81 ?? 02 00 00 00 [0-1a] 39 ?? 7c } //5
		$a_03_2 = {a0 86 45 00 c3 [0-1a] cc 35 47 00 [0-1a] e8 ?? 00 00 00 [0-1f] 31 [0-1a] 81 ?? 02 00 00 00 [0-1a] 39 ?? 7c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}