
rule Trojan_Win32_Woool_GVA_MTB{
	meta:
		description = "Trojan:Win32/Woool.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ac 80 cb 61 0f a3 db 08 c3 f5 34 55 f6 d3 68 bd 65 cd a0 fe c8 18 e3 f6 d8 66 0f ba e1 05 fe cb f6 db 34 73 8a 5c 24 08 b3 da 50 fe c8 53 aa f6 d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}