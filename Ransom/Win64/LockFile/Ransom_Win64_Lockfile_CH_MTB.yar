
rule Ransom_Win64_Lockfile_CH_MTB{
	meta:
		description = "Ransom:Win64/Lockfile.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 6d 73 69 5f 62 79 70 61 73 73 2e 72 73 } //2 amsi_bypass.rs
		$a_01_1 = {63 72 65 64 65 6e 74 69 61 6c 73 2e 72 73 } //2 credentials.rs
		$a_01_2 = {70 65 72 73 69 73 74 65 6e 63 65 2e 72 73 } //2 persistence.rs
		$a_01_3 = {61 6e 74 69 5f 61 6e 61 6c 79 73 69 73 2e 72 73 } //2 anti_analysis.rs
		$a_01_4 = {64 6e 73 5f 74 75 6e 6e 65 6c 69 6e 67 2e 72 73 } //2 dns_tunneling.rs
		$a_01_5 = {61 6e 61 6c 79 73 69 73 5f 74 6f 6f 6c 5f 64 65 74 65 63 74 65 64 } //2 analysis_tool_detected
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}