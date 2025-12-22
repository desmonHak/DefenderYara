
rule Trojan_Win64_Shelma_PGSH_MTB{
	meta:
		description = "Trojan:Win64/Shelma.PGSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {f3 41 0f 6f 04 07 48 8d 49 ?? 83 c2 ?? 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 0c 07 f3 0f 6f 41 ?? 66 0f 6f ca 0f 57 c2 f3 41 0f 7f 44 07 ?? f3 41 0f 6f 44 07 ?? 0f 57 c8 f3 41 0f 7f 4c 07 ?? f3 41 0f 6f 44 07 ?? 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 4c 07 ?? 48 83 c0 ?? 48 3d ?? ?? ?? ?? 7c } //5
		$a_03_1 = {f3 0f 6f 40 ?? 48 8d 40 ?? 66 0f 6f ca 0f 57 c8 f3 0f 7f 48 ?? 66 0f 6f ca f3 0f 6f 40 ?? 0f 57 c2 f3 0f 7f 40 ?? f3 0f 6f 40 ?? 0f 57 c8 f3 0f 7f 48 ?? 66 0f 6f ca f3 0f 6f 40 ?? 0f 57 c8 f3 0f 7f 48 ?? 48 83 ea 01 75 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}