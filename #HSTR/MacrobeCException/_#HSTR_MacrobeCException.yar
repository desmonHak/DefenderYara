
rule _#HSTR_MacrobeCException{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {40 61 72 69 73 74 6f 63 72 61 74 2e 63 6f 6d } //1 @aristocrat.com
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_2{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {49 6e 53 74 72 52 65 76 28 41 64 49 6e 66 6f 2c 20 22 44 43 3d 65 78 70 72 65 73 73 6d 61 72 65 65 22 } //1 InStrRev(AdInfo, "DC=expressmaree"
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_3{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {50 4e 31 20 2d 20 45 52 50 20 50 72 6f 64 75 63 74 69 6f 6e } //1 PN1 - ERP Production
		$a_00_1 = {4b 54 33 20 4f 76 65 72 76 69 65 77 } //1 KT3 Overview
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_4{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {49 66 20 44 69 72 28 22 63 3a 5c 63 6d 73 5c 69 6e 69 5c 77 6f 72 64 4f 70 74 4d 61 63 72 6f 2e 69 6e 69 2e 73 76 5f 6b 79 6f 64 6f 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir("c:\cms\ini\wordOptMacro.ini.sv_kyodo") = "" Then
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_5{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 63 3a 5c 63 61 6c 72 65 63 5c 71 75 6f 74 65 73 22 } //1 "c:\calrec\quotes"
		$a_00_1 = {67 6f 74 6f 62 72 6f 77 73 65 72 28 22 68 74 74 70 3a 2f 2f 77 77 77 2e 6d 6f 72 65 34 61 70 70 73 2e 63 6f 6d 2f } //1 gotobrowser("http://www.more4apps.com/
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_6{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 77 65 62 73 5c 71 73 5c 64 65 76 5c 69 6e 63 6c 75 64 65 5c 73 72 66 5c 64 65 76 6d 65 72 63 68 6d 61 69 6e 74 65 6e 61 6e 63 65 5c 78 6c 73 5c 74 65 6d 70 6c 61 74 65 73 5c 64 6d 6d 5f 74 65 6d 70 6c 61 74 65 2e 78 6c 73 } //1 c:\webs\qs\dev\include\srf\devmerchmaintenance\xls\templates\dmm_template.xls
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_7{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 72 69 62 75 74 65 20 49 6e 73 65 72 74 4e 65 77 52 6f 77 2e 56 42 5f 44 65 73 63 72 69 70 74 69 6f 6e 20 3d 20 22 4d 61 63 72 6f 20 72 65 63 6f 72 64 65 64 20 32 30 2f 30 39 2f 32 30 31 30 20 62 79 20 6c 63 68 65 75 6e 67 31 22 } //1 Attribute InsertNewRow.VB_Description = "Macro recorded 20/09/2010 by lcheung1"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_8{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 42 5f 4e 61 6d 65 20 3d 20 22 6d 55 74 69 6c 22 } //1 VB_Name = "mUtil"
		$a_01_1 = {56 42 5f 4e 61 6d 65 20 3d 20 22 45 64 69 67 72 61 70 68 4d 61 63 72 6f 73 22 } //1 VB_Name = "EdigraphMacros"
		$a_01_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 75 66 52 65 6e 65 77 61 6c 57 61 72 6e 69 6e 67 22 } //1 Attribute VB_Name = "ufRenewalWarning"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_9{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 69 73 65 72 20 67 75 69 64 65 6c 69 6e 65 73 20 69 20 64 6f 63 75 6d 65 6e 74 65 74 } //1 Viser guidelines i documentet
		$a_03_1 = {48 69 64 65 47 75 69 64 65 6c 69 6e 65 73 44 6f 63 20 4d 61 63 72 6f [0-05] 53 6b 6a 75 6c 65 72 20 67 75 69 64 65 6c 69 6e 65 73 20 69 20 64 6f 63 75 6d 65 6e 74 65 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule _#HSTR_MacrobeCException_10{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 79 70 65 72 69 6f 6e 20 53 6f 6c 75 74 69 6f 6e 73 2c 20 43 6f 72 70 2e } //1 Hyperion Solutions, Corp.
		$a_01_1 = {50 6c 65 61 73 65 20 69 6e 73 65 72 74 20 4f 70 65 72 61 20 50 72 6f 70 65 72 74 79 20 63 6f 64 65 } //1 Please insert Opera Property code
		$a_01_2 = {55 74 69 6c 69 7a 65 20 6f 20 42 6f 74 e3 6f 20 53 61 6c 76 61 72 20 50 6c 61 6e 69 6c 68 61 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_11{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {50 61 74 68 61 67 6f 72 61 73 20 77 69 6c 6c 20 6e 6f 77 20 73 63 61 6e 20 74 68 65 20 64 6f 63 75 6d 65 6e 74 73 20 69 6e 20 74 68 65 20 74 61 72 67 65 74 20 66 6f 6c 64 65 72 } //1 Pathagoras will now scan the documents in the target folder
		$a_00_1 = {44 6f 63 41 73 73 65 6d 62 6c 79 57 69 6e 4e 61 6d 65 3d 20 74 68 65 20 41 73 6b 54 61 62 6c 65 20 64 6f 63 } //1 DocAssemblyWinName= the AskTable doc
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule _#HSTR_MacrobeCException_12{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 63 41 64 4c 69 62 42 61 73 65 44 61 74 61 22 } //1 Attribute VB_Name = "cAdLibBaseData"
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 42 61 73 65 20 3d 20 22 30 7b 46 43 46 42 33 44 32 41 2d 41 30 46 41 2d 31 30 36 38 2d 41 37 33 38 2d 30 38 30 30 32 42 33 33 37 31 42 35 7d 22 } //1 Attribute VB_Base = "0{FCFB3D2A-A0FA-1068-A738-08002B3371B5}"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule _#HSTR_MacrobeCException_13{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 53 41 59 46 41 5f 53 45 4b 4d 45 4c 45 52 } //1 Sub SAYFA_SEKMELER
		$a_01_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 53 61 79 66 61 31 22 } //1 Attribute VB_Name = "Sayfa1"
		$a_01_2 = {73 79 66 2e 50 72 6f 74 65 63 74 20 28 22 73 68 65 6c 6c 6c 65 62 6c 65 62 69 22 29 2c 20 44 72 61 77 69 6e 67 4f 62 6a 65 63 74 73 3a 3d 54 72 75 65 } //1 syf.Protect ("shellleblebi"), DrawingObjects:=True
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#HSTR_MacrobeCException_14{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 45 42 4d 53 6f 66 74 77 61 72 65 56 65 72 73 69 6f 6e 22 29 } //10 CustomDocumentProperties("EBMSoftwareVersion")
		$a_00_1 = {43 6f 70 79 72 69 67 68 74 20 ef bf bd 20 32 30 31 32 2d 32 30 31 39 20 45 6e 64 72 65 73 20 41 63 74 75 61 72 69 61 6c 20 43 6f 6e 73 75 6c 74 69 6e 67 20 4c 4c 43 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=10
 
}
rule _#HSTR_MacrobeCException_15{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 68 6f 77 49 6e 73 74 72 75 63 74 69 6f 6e 73 2e 56 42 5f 44 65 73 63 72 69 70 74 69 6f 6e 20 3d 20 22 4d 61 63 72 6f 20 72 65 63 6f 72 64 65 64 20 32 39 2d 30 36 2d 32 30 30 39 20 62 79 20 4d 65 6c 69 73 73 61 20 52 6f 62 65 72 74 73 22 } //1 ShowInstructions.VB_Description = "Macro recorded 29-06-2009 by Melissa Roberts"
		$a_00_1 = {50 72 6f 6a 65 63 74 2e 4e 65 77 4d 61 63 72 6f 73 2e 48 69 64 65 49 6e 73 74 72 75 63 74 69 6f 6e 73 } //1 Project.NewMacros.HideInstructions
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule _#HSTR_MacrobeCException_16{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 47 65 74 5f 45 6d 70 6c 6f 79 65 65 5f 4e 75 6d 62 65 72 } //1 Private Function Get_Employee_Number
		$a_01_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 61 70 70 4d 61 69 6e 22 } //1 Attribute VB_Name = "appMain"
		$a_01_2 = {4d 34 41 50 53 5f 70 61 63 6b 61 67 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 6d 34 61 70 73 5f 74 72 61 6e 73 77 69 7a 61 72 64 22 } //1 M4APS_package As String = "m4aps_transwizard"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#HSTR_MacrobeCException_17{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4d 6f 64 75 6c 65 36 22 } //1 Attribute VB_Name = "Module6"
		$a_00_1 = {53 75 62 20 42 45 4f 5f 55 70 64 61 74 65 45 45 73 28 29 } //1 Sub BEO_UpdateEEs()
		$a_00_2 = {42 45 4f 5f 55 70 64 61 74 65 45 45 73 20 4d 61 63 72 6f } //1 BEO_UpdateEEs Macro
		$a_00_3 = {43 6f 6e 73 74 20 73 74 72 50 61 73 73 20 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 73 76 74 69 6d 65 73 68 65 65 74 22 } //1 Const strPass  As String = "csvtimesheet"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}
rule _#HSTR_MacrobeCException_18{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 5a 69 67 57 61 72 65 5c 42 72 61 6e 64 69 63 } //1 Software\ZigWare\Brandic
		$a_00_1 = {54 68 69 73 20 73 6f 66 74 77 61 72 65 20 69 73 20 6f 77 6e 65 64 20 62 79 20 5a 49 47 57 41 52 45 20 47 6d 62 48 } //1 This software is owned by ZIGWARE GmbH
		$a_00_2 = {53 61 76 65 53 65 74 74 69 6e 67 20 22 42 72 61 6e 64 69 63 22 2c 20 22 44 65 76 65 6c 6f 70 6d 65 6e 74 22 2c 20 22 44 65 62 75 67 4d 6f 64 65 22 2c 20 22 4f 4e 22 } //1 SaveSetting "Brandic", "Development", "DebugMode", "ON"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#HSTR_MacrobeCException_19{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 4e 61 6d 65 20 3d 20 47 65 74 41 70 70 44 61 74 61 46 6f 6c 64 65 72 28 29 20 2b 20 22 5c 4d 65 74 61 64 61 74 61 45 76 69 64 65 6e 63 65 46 69 6c 65 2e 78 6d 6c 22 } //1 fileName = GetAppDataFolder() + "\MetadataEvidenceFile.xml"
		$a_01_1 = {43 61 6c 6c 20 41 64 64 43 75 73 74 44 6f 63 50 72 6f 70 28 22 53 69 67 6e 6f 66 66 20 22 20 2b 20 43 53 74 72 28 73 69 67 6e 6f 66 66 4e 6f 64 65 49 6e 64 65 78 20 2b 20 31 29 2c 20 73 69 67 6e 6f 66 66 29 } //1 Call AddCustDocProp("Signoff " + CStr(signoffNodeIndex + 1), signoff)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#HSTR_MacrobeCException_20{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 45 78 70 6f 72 74 65 72 50 44 46 32 28 29 } //1 Sub ExporterPDF2()
		$a_01_1 = {64 69 72 42 75 72 65 61 75 20 3d 20 57 73 68 53 68 65 6c 6c 28 22 64 65 73 6b 74 6f 70 22 29 } //1 dirBureau = WshShell("desktop")
		$a_01_2 = {41 63 74 69 76 65 53 68 65 65 74 2e 45 78 70 6f 72 74 41 73 46 69 78 65 64 46 6f 72 6d 61 74 20 54 79 70 65 3a 3d 78 6c 54 79 70 65 50 44 46 2c 20 46 69 6c 65 6e 61 6d 65 3a 3d 20 5f } //1 ActiveSheet.ExportAsFixedFormat Type:=xlTypePDF, Filename:= _
		$a_01_3 = {44 61 74 65 41 75 6a 6f 75 72 64 68 75 69 20 26 20 22 2e 70 64 66 22 } //1 DateAujourdhui & ".pdf"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#HSTR_MacrobeCException_21{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4d 73 67 47 6c 6f 62 61 6c 22 } //1 Attribute VB_Name = "MsgGlobal"
		$a_00_1 = {27 2a 20 20 20 20 20 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 32 30 30 35 20 41 67 69 6c 65 6e 74 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 2c } //1 '*     Copyright (c) 2005 Agilent Technologies,
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 4d 53 47 5f 53 45 4c 45 43 54 5f 50 4f 52 54 } //1 Public Const MSG_SELECT_PORT
		$a_00_3 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 54 52 5f 41 53 53 49 47 4e 5f 45 52 52 4f 52 } //1 Public Const STR_ASSIGN_ERROR
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#HSTR_MacrobeCException_22{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 5c 5c 66 73 70 72 64 30 31 6e 5c 52 6f 6f 74 5c 47 65 72 5f 46 61 74 5f 56 61 72 65 6a 6f 5f 47 64 65 73 5f 43 74 61 73 5c 46 61 74 75 72 61 6d 65 6e 74 6f 5c 47 65 72 6f 74 20 2d 20 43 61 64 61 73 74 72 6f 5c 41 6a 75 73 74 65 20 64 65 20 43 61 64 61 73 74 72 6f 5c 54 45 53 54 45 22 } //2 "\\fsprd01n\Root\Ger_Fat_Varejo_Gdes_Ctas\Faturamento\Gerot - Cadastro\Ajuste de Cadastro\TESTE"
		$a_01_1 = {47 6c 6f 76 69 61 2e 47 6c 6f 76 69 61 43 6f 6e 6e 65 63 74 } //1 Glovia.GloviaConnect
		$a_01_2 = {22 4c 3a 5c 53 6e 61 67 67 69 6e 67 5c 43 52 45 20 53 6e 61 67 67 69 6e 67 5c 22 } //1 "L:\Snagging\CRE Snagging\"
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#HSTR_MacrobeCException_23{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 68 74 74 70 3a 2f 2f 65 6e 64 72 65 73 61 63 74 75 61 72 69 61 6c 2e 63 6f 6d 2f } //1 "http://endresactuarial.com/
		$a_01_1 = {47 65 74 53 65 74 74 69 6e 67 58 28 22 45 41 43 22 2c 20 45 41 43 54 69 74 6c 65 34 2c 20 22 41 67 72 65 65 64 22 2c 20 22 22 29 } //1 GetSettingX("EAC", EACTitle4, "Agreed", "")
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 50 72 69 6e 74 42 61 72 28 6d 5f 63 6f 64 65 2c 20 6d 5f 48 65 69 67 68 74 } //1 Function PrintBar(m_code, m_Height
		$a_01_3 = {74 5f 42 41 52 5f 50 61 74 74 65 72 6e 20 3d 20 41 72 72 61 79 28 22 31 31 30 31 31 30 30 31 31 30 30 22 } //1 t_BAR_Pattern = Array("11011001100"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
rule _#HSTR_MacrobeCException_24{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 70 70 74 49 6e 69 46 69 6c 65 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 22 20 26 20 41 44 44 49 4e 49 44 20 26 20 22 5c 58 70 70 74 2e 69 6e 69 22 } //1 XpptIniFile = Environ$("APPDATA") & "\" & ADDINID & "\Xppt.ini"
		$a_01_1 = {58 50 50 54 20 41 64 64 2d 49 6e 20 69 73 20 64 65 73 69 67 6e 65 64 20 66 6f 72 20 50 6f 77 65 72 20 50 6f 69 6e 74 } //1 XPPT Add-In is designed for Power Point
		$a_01_2 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 4d 4f 44 55 4c 45 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 6d 6f 64 41 75 74 6f 4f 70 65 6e 22 } //1 Private Const MODULE As String = "modAutoOpen"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule _#HSTR_MacrobeCException_25{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 74 72 61 63 6b 65 72 2e 63 69 76 61 73 2e 63 6f 2f 55 73 65 72 54 72 61 63 6b 65 72 5f 64 65 70 6c 6f 79 2f 72 65 71 75 65 73 74 68 61 6e 64 6c 65 72 2e 61 73 70 78 } //1 URL = "http://tracker.civas.co/UserTracker_deploy/requesthandler.aspx
		$a_01_1 = {73 54 65 6d 70 6c 61 74 65 4e 61 6d 65 20 3d 20 22 52 4f 49 20 4d 75 6c 74 69 2d 54 65 6e 61 6e 74 20 44 69 72 43 61 70 } //1 sTemplateName = "ROI Multi-Tenant DirCap
		$a_01_2 = {49 66 20 63 2e 54 69 74 6c 65 20 3d 20 22 41 73 67 6e 2e 49 6e 74 65 72 65 73 74 73 41 70 70 72 61 69 73 65 64 22 20 54 68 65 6e } //1 If c.Title = "Asgn.InterestsAppraised" Then
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#HSTR_MacrobeCException_26{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 72 69 76 61 74 65 20 53 75 62 20 57 6f 72 6b 73 68 65 65 74 5f 90 1d 20 00 28 42 79 56 61 6c 20 54 61 72 67 65 74 20 41 73 20 52 61 6e 67 } //1
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 43 6f 6e 74 72 6f 6c 20 3d 20 22 43 42 45 78 70 69 72 69 6e 67 2c 20 38 2c 20 30 2c 20 4d 53 46 6f 72 6d 73 2c 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 22 } //1 Attribute VB_Control = "CBExpiring, 8, 0, MSForms, CommandButton"
		$a_00_2 = {53 68 65 65 74 73 28 22 57 6f 72 6b 53 68 65 65 74 22 29 2e 55 6e 70 72 6f 74 65 63 74 20 50 61 73 73 77 6f 72 64 3a 3d 22 62 65 6e 6e 79 22 } //1 Sheets("WorkSheet").Unprotect Password:="benny"
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#HSTR_MacrobeCException_27{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 09 00 00 "
		
	strings :
		$a_00_0 = {54 65 6b 45 78 63 65 6c 54 6f 6f 6c 62 61 72 2e 78 6c 61 } //1 TekExcelToolbar.xla
		$a_00_1 = {44 6c 67 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c } //1 DlgInternational
		$a_00_2 = {41 34 2f 6c 65 74 74 65 72 20 72 65 73 69 7a 65 } //1 A4/letter resize
		$a_00_3 = {4c 61 62 65 6c 5f 46 72 65 65 34 43 6f 72 70 } //1 Label_Free4Corp
		$a_00_4 = {4f 72 61 63 6c 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Oracle Corporation
		$a_00_5 = {67 65 6e 65 72 61 74 65 64 20 62 79 20 43 6f 6e 63 65 70 74 } //1 generated by Concept
		$a_00_6 = {49 6e 74 65 6c 6c 75 74 69 6f 6e 2c } //1 Intellution,
		$a_00_7 = {4c 69 6e 75 78 46 6f 72 6d 20 46 6f 72 6d } //1 LinuxForm Form
		$a_00_8 = {61 6c 6c 65 6e 20 4d 6f 64 75 6c 65 6e 20 73 74 65 68 65 6e } //1 allen Modulen stehen
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_28{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 63 6d 73 43 61 6e 63 65 6c 52 75 62 69 28 29 } //1 Public Sub cmsCancelRubi()
		$a_01_1 = {63 2e 52 75 6e 20 28 22 43 61 6e 63 65 6c 52 75 62 69 22 29 } //1 c.Run ("CancelRubi")
		$a_01_2 = {50 75 62 6c 69 63 20 53 75 62 20 63 6d 73 4f 76 65 72 77 69 74 65 53 61 76 65 46 69 6c 65 28 29 } //1 Public Sub cmsOverwiteSaveFile()
		$a_01_3 = {63 2e 52 75 6e 20 28 22 4f 76 65 72 77 69 74 65 53 61 76 65 46 69 6c 65 22 29 } //1 c.Run ("OverwiteSaveFile")
		$a_01_4 = {50 75 62 6c 69 63 20 53 75 62 20 63 6d 73 53 61 76 65 46 69 6c 65 4e 61 6d 69 6e 67 28 29 } //1 Public Sub cmsSaveFileNaming()
		$a_01_5 = {63 2e 52 75 6e 20 28 22 53 61 76 65 46 69 6c 65 4e 61 6d 69 6e 67 22 29 } //1 c.Run ("SaveFileNaming")
		$a_01_6 = {53 65 74 20 63 20 3d 20 47 65 74 4d 61 6e 61 67 65 64 43 6c 61 73 73 28 4d 65 29 } //1 Set c = GetManagedClass(Me)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule _#HSTR_MacrobeCException_29{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {49 66 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 44 4e 53 44 4f 4d 41 49 4e 22 29 20 4c 69 6b 65 20 22 2a 2e 43 50 51 43 4f 52 50 2e 4e 45 54 22 20 4f 72 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 44 4e 53 44 4f 4d 41 49 4e 22 29 20 4c 69 6b 65 20 22 2a 53 56 43 2e 41 43 43 45 4e 54 55 52 45 2e 43 4f 4d 22 20 4f 72 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 44 4e 53 44 4f 4d 41 49 4e 22 29 20 4c 69 6b 65 20 22 2a 41 55 54 48 2a 48 50 49 43 4f 52 50 2e 4e 45 54 22 20 54 68 65 6e } //1 If Environ("USERDNSDOMAIN") Like "*.CPQCORP.NET" Or Environ("USERDNSDOMAIN") Like "*SVC.ACCENTURE.COM" Or Environ("USERDNSDOMAIN") Like "*AUTH*HPICORP.NET" Then
		$a_00_1 = {73 74 72 55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 75 6e 2d 62 63 2e 70 65 74 72 6f 62 72 61 73 2e 63 6f 6d 2e 62 72 2f 61 70 6c 69 63 61 74 69 76 6f 2f 6c 69 } //1 strURL = "http://www.un-bc.petrobras.com.br/aplicativo/li
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_30{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 63 6d 73 44 69 73 70 6c 61 79 43 6f 6e 74 72 6f 6c 52 75 62 69 28 29 } //1 Public Sub cmsDisplayControlRubi()
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 63 6d 73 52 65 6d 61 6b 65 44 6f 63 43 6f 6d 6d 61 6e 64 73 28 29 } //1 Public Sub cmsRemakeDocCommands()
		$a_00_2 = {50 75 62 6c 69 63 20 53 75 62 20 63 6d 73 53 65 74 57 6f 72 64 4f 70 74 28 29 } //1 Public Sub cmsSetWordOpt()
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 63 6d 73 53 65 74 42 72 65 61 6b 28 29 } //1 Public Sub cmsSetBreak()
		$a_00_4 = {50 75 62 6c 69 63 20 53 75 62 20 63 6d 73 53 65 6e 64 4d 61 6e 75 73 63 72 69 70 74 28 29 } //1 Public Sub cmsSendManuscript()
		$a_00_5 = {4f 70 74 69 6f 6e 73 2e 41 75 74 6f 46 6f 72 6d 61 74 41 73 59 6f 75 54 79 70 65 52 65 70 6c 61 63 65 46 61 72 45 61 73 74 44 61 73 68 65 73 20 3d 20 46 61 6c 73 65 } //1 Options.AutoFormatAsYouTypeReplaceFarEastDashes = False
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule _#HSTR_MacrobeCException_31{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 72 69 76 61 74 65 20 53 75 62 20 57 6f 72 6b 73 68 65 65 74 5f 90 1d 20 00 28 42 79 56 61 6c 20 54 61 72 67 65 74 20 41 73 20 52 61 6e 67 } //1
		$a_00_1 = {6e 61 6d 65 20 3d 20 54 79 70 20 26 20 22 5f 6d 6f 64 65 5f 22 20 26 20 65 78 74 65 6e 73 69 6f 6e 20 26 20 22 2e 74 6d 2e 73 70 63 64 72 76 22 } //1 name = Typ & "_mode_" & extension & ".tm.spcdrv"
		$a_00_2 = {4c 69 63 65 6e 73 65 41 67 72 65 65 6d 65 6e 74 5f 42 33 30 2e 53 68 6f 77 45 75 6c 61 49 66 4e 65 65 64 65 64 20 22 53 6f 66 74 77 61 72 65 5c 44 65 73 69 67 6e 20 43 6f 6e 74 72 6f 6c 20 53 6f 66 74 77 61 72 65 5c 4d 65 61 73 75 72 65 73 20 6d 61 73 74 65 72 69 6e 67 20 68 65 6c 70 65 72 5c 50 72 6f 74 6f 74 79 70 65 20 73 65 74 74 69 6e 67 20 68 65 6c 70 65 72 22 } //1 LicenseAgreement_B30.ShowEulaIfNeeded "Software\Design Control Software\Measures mastering helper\Prototype setting helper"
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#HSTR_MacrobeCException_32{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 0b 00 00 "
		
	strings :
		$a_00_0 = {54 65 6b 45 78 63 65 6c 54 6f 6f 6c 62 61 72 2e 78 6c 61 } //1 TekExcelToolbar.xla
		$a_00_1 = {44 6c 67 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c } //1 DlgInternational
		$a_00_2 = {53 61 69 66 6f 6e 20 44 6f 72 69 7a 7a 69 } //1 Saifon Dorizzi
		$a_00_3 = {42 6c 6f 6f 6d 62 65 72 67 20 4c 50 } //1 Bloomberg LP
		$a_00_4 = {57 6f 72 6c 65 79 50 61 72 73 6f 6e 73 } //1 WorleyParsons
		$a_00_5 = {55 73 65 72 54 72 61 63 6b 65 72 5f 64 65 70 6c 6f 79 } //1 UserTracker_deploy
		$a_00_6 = {28 22 42 61 73 65 5f 4d 65 73 22 29 2e 56 69 73 69 62 6c 65 } //1 ("Base_Mes").Visible
		$a_00_7 = {41 53 41 73 75 6d 6d 61 72 79 } //1 ASAsummary
		$a_00_8 = {77 77 77 2e 6f 72 69 6d 69 2e 63 6f 6d 2f 70 64 66 2d 74 65 73 74 2e 70 64 66 } //1 www.orimi.com/pdf-test.pdf
		$a_00_9 = {53 6f 66 74 77 61 72 65 5c 5c 53 63 68 6d 61 6c 65 47 6d 62 48 } //1 Software\\SchmaleGmbH
		$a_00_10 = {50 72 69 76 61 74 65 20 53 75 62 20 6d 64 35 5f 74 72 61 6e 73 66 6f 72 6d 28 73 74 61 74 65 28 29 } //1 Private Sub md5_transform(state()
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_33{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 76 65 6e 74 6f 72 79 43 6f 75 6e 74 6c 69 73 74 56 42 41 2e 48 61 6e 64 6c 65 57 6f 72 6b 62 6f 6f 6b 42 65 66 6f 72 65 53 61 76 65 28 73 61 76 65 41 73 55 49 29 } //1 InventoryCountlistVBA.HandleWorkbookBeforeSave(saveAsUI)
		$a_01_1 = {56 61 6c 69 64 61 74 65 43 6f 75 6e 74 6c 69 73 74 4f 74 68 65 72 42 61 74 63 68 41 6e 64 53 65 72 69 61 6c 6e 75 6d 62 65 72 20 65 78 63 65 6c 52 61 6e 67 65 2e 52 6f 77 2c 20 46 61 6c 73 65 2c 20 54 72 75 65 } //1 ValidateCountlistOtherBatchAndSerialnumber excelRange.Row, False, True
		$a_01_2 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 4d 4f 44 55 4c 45 5f 4e 41 4d 45 20 3d 20 22 43 6f 75 6e 74 6c 69 73 74 4f 74 68 65 72 22 } //1 Private Const MODULE_NAME = "CountlistOther"
		$a_01_3 = {65 57 6f 72 6b 73 49 4f 2e 53 61 76 65 46 69 6c 65 20 22 74 6f 72 74 6f 69 73 65 70 72 6f 63 2e 65 78 65 20 2f 63 6f 6d 6d 61 6e 64 3a 63 6f 6d 6d 69 74 20 2f 70 61 74 68 3a 22 22 22 20 26 20 76 62 61 52 65 70 6f 73 69 74 6f 72 79 50 61 74 68 20 26 20 22 22 22 20 2f 63 6c 6f 73 65 6f 6e 65 6e 64 3a 31 } //1 eWorksIO.SaveFile "tortoiseproc.exe /command:commit /path:""" & vbaRepositoryPath & """ /closeonend:1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#HSTR_MacrobeCException_34{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 49 4e 47 5f 5f 53 61 6c 65 43 6f 64 65 5f 41 6e 61 6c 79 73 65 22 } //1 Attribute VB_Name = "ING__SaleCode_Analyse"
		$a_01_1 = {43 61 6c 6c 20 75 70 64 61 74 65 5f 63 6f 75 6e 74 28 22 7a 5f 49 4e 47 5f 5f 53 61 6c 65 43 6f 64 65 5f 41 6e 61 6c 79 73 65 22 29 } //1 Call update_count("z_ING__SaleCode_Analyse")
		$a_01_2 = {2e 56 61 6c 75 65 20 3d 20 22 52 65 74 72 69 65 76 69 6e 67 20 56 45 51 42 20 64 61 74 61 2e 2e 2e 22 } //1 .Value = "Retrieving VEQB data..."
		$a_01_3 = {2e 56 61 6c 75 65 20 3d 20 22 4c 6f 67 20 6f 6e 20 72 65 67 69 6f 6e 20 27 22 20 26 20 52 45 47 49 4f 4e 5f 50 4c 41 4e 54 } //1 .Value = "Log on region '" & REGION_PLANT
		$a_01_4 = {2e 56 61 6c 75 65 20 3d 20 45 78 63 65 6c 2e 53 68 65 65 74 73 28 22 42 4f 4d 2d 52 45 53 55 4c 54 22 29 2e 52 61 6e 67 65 28 72 65 73 75 6c 74 5f 61 63 65 6c 6c 29 } //1 .Value = Excel.Sheets("BOM-RESULT").Range(result_acell)
		$a_01_5 = {46 75 6e 63 74 69 6f 6e 20 43 68 65 63 6b 5f 73 61 6c 65 63 6f 64 65 24 28 43 48 41 53 53 49 53 2c 20 73 63 2c 20 52 45 47 49 4f 4e 5f 50 4c 41 4e 54 29 } //1 Function Check_salecode$(CHASSIS, sc, REGION_PLANT)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
rule _#HSTR_MacrobeCException_35{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_00_0 = {44 61 74 65 3a 20 32 30 31 34 2d 31 30 2d 32 30 3a 20 63 68 61 6e 67 65 64 20 6d 65 74 68 6f 64 20 6f 66 20 73 75 6d 6d 69 6e 67 20 6c 69 6e 65 73 20 2d 20 74 6f 74 61 6c 20 77 6f 72 64 73 20 71 75 61 6e 74 69 74 79 20 2f 20 77 6f 72 64 73 70 65 72 6c 69 6e 65 } //1 Date: 2014-10-20: changed method of summing lines - total words quantity / wordsperline
		$a_01_1 = {53 68 65 65 74 73 28 22 53 74 61 72 74 55 70 22 29 2e 56 69 73 69 62 6c 65 20 3d 20 4e 6f 74 20 62 6c 6e 56 69 73 69 62 6c 65 } //1 Sheets("StartUp").Visible = Not blnVisible
		$a_01_2 = {53 68 65 65 74 73 28 22 53 44 41 54 45 30 30 22 29 2e 41 63 74 69 76 61 74 65 } //1 Sheets("SDATE00").Activate
		$a_01_3 = {78 52 65 66 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 50 44 46 43 72 65 61 74 6f 72 5c 50 44 46 43 72 65 61 74 6f 72 2e 65 78 65 22 } //1 xRef = "C:\Program Files (x86)\PDFCreator\PDFCreator.exe"
		$a_01_4 = {68 74 74 70 3a 2f 2f 67 6c 6f 62 61 6c 69 6e 6b 2f 66 69 6e 61 6e 63 65 6e 65 74 } //1 http://globalink/financenet
		$a_01_5 = {49 66 20 57 6f 72 6b 62 6f 6f 6b 73 28 22 44 61 4d 65 6e 75 2e 78 6c 73 22 29 2e 50 61 74 68 20 26 20 22 5c 42 41 43 4b 55 50 22 20 3d 20 6c 62 6c 50 61 74 68 2e 43 61 70 74 69 6f 6e 20 54 68 65 6e } //1 If Workbooks("DaMenu.xls").Path & "\BACKUP" = lblPath.Caption Then
		$a_01_6 = {45 4e 44 5f 50 4f 49 4e 54 5f 44 45 56 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 68 74 74 70 73 3a 2f 2f 64 65 76 63 65 6c 6c 73 65 67 6f 76 61 70 69 77 65 62 61 70 70 2e 61 7a 75 72 65 77 65 62 73 69 74 65 73 2e 6e 65 74 2f 22 } //1 END_POINT_DEV As String = "https://devcellsegovapiwebapp.azurewebsites.net/"
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=1
 
}
rule _#HSTR_MacrobeCException_36{
	meta:
		description = "!#HSTR:MacrobeCException,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 15 00 00 "
		
	strings :
		$a_01_0 = {53 75 6e 47 61 72 64 } //1 SunGard
		$a_01_1 = {40 74 64 2e 63 6f 6d 22 } //1 @td.com"
		$a_00_2 = {55 70 64 61 74 65 4c 69 6e 6b 20 4e 61 6d 65 3a 3d 22 43 3a 5c 52 61 74 65 20 56 69 65 77 5c } //1 UpdateLink Name:="C:\Rate View\
		$a_00_3 = {2e 75 6b 2e 63 62 69 2e 63 6f 6d 2f 6f 75 74 67 6f 69 6e 67 } //1 .uk.cbi.com/outgoing
		$a_00_4 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 42 65 72 65 63 68 6e 75 6e 67 65 6e 22 } //1 Attribute VB_Name = "Berechnungen"
		$a_00_5 = {22 73 70 65 63 67 72 6f 75 70 2f 73 70 65 63 5b 6e 61 6d 65 3d 27 } //1 "specgroup/spec[name='
		$a_00_6 = {43 72 65 61 74 65 46 69 6c 74 65 72 53 74 72 69 6e 67 28 22 45 7a 41 70 70 20 46 69 6c 65 73 20 28 45 7a 41 70 70 2a 2e 78 6c 73 29 22 } //1 CreateFilterString("EzApp Files (EzApp*.xls)"
		$a_00_7 = {27 57 72 69 74 74 65 6e 20 62 79 20 52 75 73 73 65 6c 6c 20 4b 75 65 6d 70 65 72 } //1 'Written by Russell Kuemper
		$a_00_8 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 72 65 65 6e 70 61 72 74 6e 65 72 73 68 69 70 2e 6a 70 } //1 http://www.greenpartnership.jp
		$a_00_9 = {41 64 64 69 6e 73 6f 66 74 20 61 72 65 20 72 65 67 69 73 74 65 72 65 64 20 74 72 61 64 65 6d 61 72 6b 73 20 6f 66 20 41 64 64 69 6e 73 6f 66 74 2e } //1 Addinsoft are registered trademarks of Addinsoft.
		$a_00_10 = {54 72 61 66 66 69 63 5f 43 65 6e 74 72 61 6c 5f 41 75 74 6f 6d 61 74 69 6f 6e } //1 Traffic_Central_Automation
		$a_00_11 = {68 74 74 70 3a 2f 2f 64 61 66 73 68 61 72 65 2d 6f 72 67 2e 65 75 2e 70 61 63 63 61 72 2e 63 6f 6d } //1 http://dafshare-org.eu.paccar.com
		$a_00_12 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 54 65 78 74 20 46 69 6c 65 6e 61 6d 65 3a 3d 22 50 3a 5c 46 54 50 5c 4d 61 72 6b 65 74 69 6e 67 5c 44 6f 77 6e 6c 6f 61 64 } //1 Workbooks.OpenText Filename:="P:\FTP\Marketing\Download
		$a_00_13 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 6c 63 6f 6d 2e 61 64 6d 69 6e 2e 63 68 } //1 https://www.elcom.admin.ch
		$a_00_14 = {50 72 6f 20 4b 69 6e 64 20 62 65 74 72 e4 67 74 20 64 65 72 20 48 f6 63 68 73 74 61 6e 73 61 74 7a } //1
		$a_00_15 = {45 72 73 74 61 74 74 75 6e 67 73 61 6e 73 70 72 75 63 68 20 47 65 72 69 63 68 74 73 6b 6f 73 74 65 6e } //1 Erstattungsanspruch Gerichtskosten
		$a_00_16 = {28 63 29 20 54 68 6f 6d 61 73 20 57 69 6c 6d 65 73 } //1 (c) Thomas Wilmes
		$a_00_17 = {54 68 6f 6d 61 73 20 42 6c f6 6d 6b 65 72 } //1
		$a_00_18 = {56 3a 5c 43 6f 6d 6d 6f 64 69 74 69 65 73 5c 47 53 43 49 5c 52 54 52 5c 43 53 50 5c 43 53 50 44 45 4c 54 41 2e 63 73 76 } //1 V:\Commodities\GSCI\RTR\CSP\CSPDELTA.csv
		$a_00_19 = {22 68 74 74 70 3a 2f 2f 77 77 77 2e 6b 73 73 6f 66 74 77 61 72 65 2e 63 68 } //1 "http://www.kssoftware.ch
		$a_00_20 = {4d 73 67 42 6f 78 20 4d 45 5f 4d 55 53 54 5f 48 41 53 53 45 49 4e 4f 2c } //1 MsgBox ME_MUST_HASSEINO,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*1+(#a_00_20  & 1)*1) >=1
 
}