
rule HackTool_Linux_CredShadow_C{
	meta:
		description = "HackTool:Linux/CredShadow.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {61 00 77 00 6b 00 20 00 2f 00 2f 00 20 00 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00 } //1 awk // /etc/shadow
	condition:
		((#a_00_0  & 1)*1) >=1
 
}