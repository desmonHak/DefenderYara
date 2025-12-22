
rule Trojan_Win64_XWorm_GAPF_MTB{
	meta:
		description = "Trojan:Win64/XWorm.GAPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_81_0 = {45 6a 65 63 75 74 61 6e 64 6f 20 73 68 65 6c 6c 63 6f 64 65 } //8 Ejecutando shellcode
		$a_81_1 = {70 61 79 6c 6f 61 64 2e 65 6e 63 } //1 payload.enc
		$a_81_2 = {53 68 65 6c 6c 63 6f 64 65 20 65 6a 65 63 75 74 61 64 6f } //1 Shellcode ejecutado
	condition:
		((#a_81_0  & 1)*8+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=10
 
}