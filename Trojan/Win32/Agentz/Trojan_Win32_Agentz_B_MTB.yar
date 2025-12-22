
rule Trojan_Win32_Agentz_B_MTB{
	meta:
		description = "Trojan:Win32/Agentz.B!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 61 49 ff 72 74 6e ff 77 57 00 ff 5f 70 6f ff 79 42 00 ff 6f 68 63 ff 36 31 47 ff 69 66 48 ff 67 45 57 ff 4f 74 65 ff 44 70 6f ff 72 00 76 ff 6e 42 4b ff 57 78 38 ff 4f 70 49 ff 00 72 65 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}