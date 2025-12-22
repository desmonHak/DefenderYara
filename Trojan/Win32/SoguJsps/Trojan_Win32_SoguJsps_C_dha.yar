
rule Trojan_Win32_SoguJsps_C_dha{
	meta:
		description = "Trojan:Win32/SoguJsps.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8e 4e 0e ec [0-0c] 81 [0-03] aa fc 0d 7c [0-0c] 81 [0-03] 54 ca af 91 [0-0c] 81 [0-03] 1b c6 46 79 90 09 04 00 [0-02] 81 } //1
		$a_02_1 = {6a 04 68 00 30 00 00 8b [0-20] 00 00 c0 03 ?? 6a 00 ff 55 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}