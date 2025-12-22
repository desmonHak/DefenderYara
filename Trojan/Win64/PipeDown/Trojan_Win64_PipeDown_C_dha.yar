
rule Trojan_Win64_PipeDown_C_dha{
	meta:
		description = "Trojan:Win64/PipeDown.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 ?? ?? 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 45 00 64 00 67 00 65 00 5c 00 45 00 64 00 67 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 } //1
		$a_02_1 = {47 6c 6f 62 61 6c 5c 53 69 6e 67 6c 65 43 6f 72 ?? 6f 72 61 74 69 6f 6e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}