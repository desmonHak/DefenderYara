
rule Trojan_Win32_AsyncRAT_AMTB{
	meta:
		description = "Trojan:Win32/AsyncRAT!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_80_0 = {6d 65 70 20 20 20 70 65 53 70 65 53 65 70 20 20 20 70 65 53 70 65 53 65 70 20 20 20 70 65 53 70 65 53 65 70 20 20 20 70 65 53 70 65 53 65 70 20 20 20 70 65 53 70 65 53 65 70 20 20 20 70 65 53 70 65 53 65 70 20 20 20 70 65 53 70 65 53 65 70 20 20 20 70 65 53 70 65 53 65 70 20 20 20 70 65 53 70 65 53 65 70 } //mep   peSpeSep   peSpeSep   peSpeSep   peSpeSep   peSpeSep   peSpeSep   peSpeSep   peSpeSep   peSpeSep  6
	condition:
		((#a_80_0  & 1)*6) >=6
 
}