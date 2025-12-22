
rule Ransom_PowerShell_FileFix_DZ_MTB{
	meta:
		description = "Ransom:PowerShell/FileFix.DZ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,7d 00 7d 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 Powershell
		$a_00_1 = {72 00 61 00 6e 00 73 00 6f 00 6d 00 } //10 ransom
		$a_00_2 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //10 Encrypt
		$a_00_3 = {20 00 23 00 20 00 } //5  # 
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*5) >=125
 
}