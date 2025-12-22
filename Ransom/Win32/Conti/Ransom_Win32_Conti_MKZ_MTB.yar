
rule Ransom_Win32_Conti_MKZ_MTB{
	meta:
		description = "Ransom:Win32/Conti.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 65 78 66 69 6c 74 72 61 74 65 64 20 64 61 74 61 20 70 75 62 6c 69 73 68 65 64 20 6f 6e 20 64 61 72 6b 6e 65 74 20 66 6f 72 75 6d 73 } //3 All exfiltrated data published on darknet forums
		$a_81_1 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //3 vssadmin delete shadows /all /quiet
		$a_81_2 = {52 45 43 4f 56 45 52 5f 49 4e 53 54 52 55 43 54 49 4f 4e 53 2e 68 74 6d 6c } //2 RECOVER_INSTRUCTIONS.html
		$a_81_3 = {43 6f 6e 74 61 63 74 20 4f 4e 4c 59 20 61 66 74 65 72 20 70 61 79 6d 65 6e 74 20 63 6f 6e 66 69 72 6d 61 74 69 6f 6e } //3 Contact ONLY after payment confirmation
		$a_81_4 = {43 4f 4d 50 52 4f 4d 49 53 45 44 } //2 COMPROMISED
		$a_81_5 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //2 DisableRealtimeMonitoring
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*2+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2) >=15
 
}