//#include "stdafx.h"
#include "WMIInfo.h"
#include <string>
#include "md5.h"
#include "AES.h"
#include "Base64.h"
char all[256] = "";//储存机器码
void PrintMD5(const string &str, MD5 &md5) {
	cout << "MD5(\"" << str << "\") = " << md5.toString() << endl;
}
const char g_key[17] = "asdfwetyhjuytrfd";//密钥
const char g_iv[17] = "gfdertfghjkuyrtg";//偏移量
string EncryptionAES(const string & strSrc) //AES加密
{
	size_t length = strSrc.length();
	int block_num = length / BLOCK_SIZE + 1;
	//明文
	char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
	memcpy(szDataIn, strSrc.c_str(), length + 1);


	//进行PKCS7Padding填充。
	int k = length % BLOCK_SIZE;
	int j = length / BLOCK_SIZE;
	int padding = BLOCK_SIZE - k;
	for (int i = 0; i < padding; i++)
	{
		szDataIn[j * BLOCK_SIZE + k + i] = padding;
	}
	szDataIn[block_num * BLOCK_SIZE] = '\0';

	//加密后的密文
	char *szDataOut = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

	//进行进行AES的CBC模式加密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
	string str = base64_encode((unsigned char*)szDataOut,
		block_num * BLOCK_SIZE);
	delete[] szDataIn;
	delete[] szDataOut;
	return str;
}
string DecryptionAES(const string& strSrc) //AES解密
{
	string strData = base64_decode(strSrc);
	size_t length = strData.length();
	//密文
	char *szDataIn = new char[length + 1];
	memcpy(szDataIn, strData.c_str(), length + 1);
	//明文
	char *szDataOut = new char[length + 1];
	memcpy(szDataOut, strData.c_str(), length + 1);

	//进行AES的CBC模式解密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

	//去PKCS7Padding填充
	if ((szDataOut[length - 1] > 0x00) && (szDataOut[length - 1] <= 16))
	{
		int tmp = szDataOut[length - 1];
		for (int i = length - 1; i >= (length - tmp); i--)
		{
			if (szDataOut[i] != tmp)
			{
				memset(szDataOut, 0, length);
				cout << "去填充失败！解密出错！！" << endl;
				break;
			}
			else
				szDataOut[i] = 0;
		}
	}
	string strDest(szDataOut);
	delete[] szDataIn;
	delete[] szDataOut;
	return strDest;
}
int main ()
{
	
	
	CWmiInfo WMI;
	
	WMI.InitWmi();

	// 硬盘：Model,SerialNumber
	CString strDiskModel,strDiskSerialNumber;
	WMI.GetSingleItemInfo(L"Win32_DiskDrive WHERE (SerialNumber IS NOT NULL) AND (MediaType LIKE 'Fixed hard disk%')", L"Model", strDiskModel);
	WMI.GetSingleItemInfo(L"Win32_DiskDrive WHERE (SerialNumber IS NOT NULL) AND (MediaType LIKE 'Fixed hard disk%')", L"SerialNumber", strDiskSerialNumber);
	wchar_t *DkM = strDiskSerialNumber.GetBuffer();
	wchar_t *DkSn = strDiskModel.GetBuffer();
	char Disk[256];
	WideCharToMultiByte(CP_ACP, 0, DkM, wcslen(DkM) + 1, Disk, 256, NULL, NULL);
	strcat_s(all, Disk);
	WideCharToMultiByte(CP_ACP, 0, DkM, wcslen(DkM) + 1, Disk, 256, NULL, NULL);
	strcat_s(all, Disk);
	if (!strDiskSerialNumber.IsEmpty() and !strDiskModel.IsEmpty())
	{
		wcout << "DiskModel : " << strDiskModel.GetBuffer() <<"; DiskSerialNumber:" << strDiskSerialNumber.GetBuffer()<<endl;
	}

	// 主板：Manufacturer + SerialNumber
	CString strBaseBoardManufacturer ,strBaseBoardSerialNumber;
	
	WMI.GetSingleItemInfo(L"Win32_BaseBoard WHERE (SerialNumber IS NOT NULL)", L"Manufacturer", strBaseBoardManufacturer);
	WMI.GetSingleItemInfo(L"Win32_BaseBoard WHERE (SerialNumber IS NOT NULL)", L"SerialNumber", strBaseBoardSerialNumber);
	//LPTSTR pStr = strBaseBoardManufacturer.GetBuffer();//实验的地方
	wchar_t *BbSn = strBaseBoardSerialNumber.GetBuffer();
	wchar_t *BbMa = strBaseBoardManufacturer.GetBuffer();
	char Bb[256];
	WideCharToMultiByte(CP_ACP, 0, BbMa, wcslen(BbMa) + 1, Bb, 256, NULL, NULL);
	strcat_s(all, Bb);
	WideCharToMultiByte(CP_ACP, 0, BbSn, wcslen(BbSn) + 1, Bb, 256, NULL, NULL);
	//strcat_s
	strcat_s(all ,Bb);//字符拼接

	if (!strBaseBoardSerialNumber.IsEmpty() and !strBaseBoardManufacturer.IsEmpty())
	{
		wcout << "BaseBoardManufacturer : " << strBaseBoardManufacturer.GetBuffer() ;
		wcout << "; BaseBoardSerialNumber : " << strBaseBoardSerialNumber.GetBuffer() << endl;
	}

	// CPU：Manufacturer + Name + ProcessorId
	CString strCpuManufacturer,strCpuName,strCpuProcessorID;
	WMI.GetSingleItemInfo(L"Win32_Processor WHERE (ProcessorId IS NOT NULL)", L"ProcessorId", strCpuProcessorID);//(在此处修改)
	WMI.GetSingleItemInfo(L"Win32_Processor WHERE (ProcessorId IS NOT NULL)", L"Name", strCpuName);
	WMI.GetSingleItemInfo(L"Win32_Processor WHERE (ProcessorId IS NOT NULL)", L"Manufacturer",strCpuManufacturer);
	wchar_t *CpuMa = strCpuManufacturer.GetBuffer();
	wchar_t *CpuNa = strCpuName.GetBuffer();
	wchar_t *CpuId = strCpuProcessorID.GetBuffer();
	char Cpu[256];
	WideCharToMultiByte(CP_ACP, 0, CpuMa, wcslen(CpuMa) + 1, Cpu, 256, NULL, NULL);
	strcat_s(all, Cpu);
	WideCharToMultiByte(CP_ACP, 0, CpuNa, wcslen(CpuNa) + 1, Cpu, 256, NULL, NULL);
	strcat_s(all, Cpu);
	WideCharToMultiByte(CP_ACP, 0, CpuId, wcslen(CpuId) + 1, Cpu, 256, NULL, NULL);
	strcat_s(all, Cpu);
	if (!strCpuProcessorID.IsEmpty() or !strCpuManufacturer.IsEmpty() or !strCpuName.IsEmpty())
	{
		wcout << "ProcessorId is : " << strCpuProcessorID.GetBuffer() <<" ;CpuName：" << strCpuName.GetBuffer();
		wcout << " ;CpuManufacturer ： " << strCpuManufacturer.GetBuffer()<< endl;
	}

	// BIOS  Manufacturer,SerialNumber
	CString strBIOSManufacturer,strBiosSerialNumber;
	WMI.GetSingleItemInfo(L"Win32_BIOS WHERE (SerialNumber IS NOT NULL)", L"Manufacturer", strBIOSManufacturer);
	WMI.GetSingleItemInfo(L"Win32_BIOS WHERE (SerialNumber IS NOT NULL)", L"SerialNumber", strBiosSerialNumber);
	wchar_t *BiosMa = strBIOSManufacturer.GetBuffer();
	wchar_t *BiosSn = strBiosSerialNumber.GetBuffer();
	char Bios[256];
	WideCharToMultiByte(CP_ACP, 0, BiosMa, wcslen(BiosMa) + 1, Bios, 256, NULL, NULL);
	strcat_s(all, Bios);
	WideCharToMultiByte(CP_ACP, 0, BiosSn, wcslen(BiosSn) + 1, Bios, 256, NULL, NULL);
	strcat_s(all, Bios);
	if (!strBIOSManufacturer.IsEmpty()and !strBiosSerialNumber.IsEmpty())
	{
		wcout << "BIOSManufacturer : " << strBIOSManufacturer.GetBuffer() <<"; BiosSerialNumber:" << strBiosSerialNumber .GetBuffer()<<endl;
	}
	/*
	// 网卡当前MAC地址
	CString strCurrentNetwork;
	WMI.GetSingleItemInfo(L"Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (NOT (PNPDeviceID LIKE 'ROOT%'))", L"MACAddress", strCurrentNetwork);

	if (!strCurrentNetwork.IsEmpty())
	{
		wcout << "网卡当前MAC地址: " << strCurrentNetwork.GetBuffer() << endl;
	}
	*/
	//cout << all << endl;//显示序列号
	WMI.ReleaseWmi();
	//获取 UUID 
	char *Uidd;
	Uidd = WMI.UUID();
	strcat_s(all, Uidd);
	//Md5 加密
	MD5 md5;
	md5.update(all);
	string Machine_code_Md5 = md5.toString();
	cout << Machine_code_Md5 << endl;
	//const char *pc = str1.c_str();
	cout << "加密前:" << Machine_code_Md5 << endl;
	string str2 = EncryptionAES(Machine_code_Md5);
	cout << "加密后:" << str2 << endl;
	//PrintMD5("机器码为： ", md5);
	//PrintMD5("机器码为： ", md5);
	//getchar();
	//system("pause");
	return 0;
}