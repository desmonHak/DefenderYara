
rule Backdoor_Win64_Remcos_GTD_MTB{
	meta:
		description = "Backdoor:Win64/Remcos.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {ac f8 ac 00 ad ?? ?? ?? ?? 18 ad ?? ?? ?? ?? 30 ad ?? ?? ?? ?? 48 ad 50 ad 58 ad 00 10 07 00 30 00 00 00 20 } //10
		$a_01_1 = {5c 52 41 54 5c 42 61 63 6b 64 6f 6f 72 5c 52 65 6c 65 61 73 65 5c 42 61 63 6b 64 6f 6f 72 2e 70 64 62 } //1 \RAT\Backdoor\Release\Backdoor.pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}