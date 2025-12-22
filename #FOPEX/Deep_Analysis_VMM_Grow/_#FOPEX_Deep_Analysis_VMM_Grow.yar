
rule _#FOPEX_Deep_Analysis_VMM_Grow{
	meta:
		description = "!#FOPEX:Deep_Analysis_VMM_Grow,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 08 c6 45 ?? 6e c6 45 ?? 74 c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 00 c6 45 ?? 61 c6 45 ?? 64 c6 45 ?? 76 c6 45 ?? 61 c6 45 ?? 70 c6 45 ?? 69 c6 45 ?? 33 c6 45 ?? 32 c6 45 ?? 00 } //3
		$a_03_1 = {68 ff 1f 7c c9 [0-18] 68 31 74 bc 7f } //4
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*4) >=7
 
}