
rule Trojan_Win32_SoguSec_A_dha{
	meta:
		description = "Trojan:Win32/SoguSec.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 31 32 33 34 35 36 37 38 39 41 42 43 ?? 45 46 88 13 00 00 60 ea 00 00 } //1
		$a_00_1 = {40 43 58 55 73 62 40 } //-1 @CXUsb@
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*-1) >=1
 
}