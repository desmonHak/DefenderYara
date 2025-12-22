
rule Trojan_BAT_ShellCodeRunner_GTF_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.GTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 27 06 08 8f ?? 00 00 01 25 71 ?? 00 00 01 72 ?? 00 00 70 08 1f 0a 5d 6f ?? 00 00 0a d2 61 d2 81 ?? 00 00 01 08 17 58 0c 08 07 17 59 33 d3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}