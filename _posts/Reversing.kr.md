---
title: "Reversing.kr Training practice"
description: "Practice make perfect"
summary: "Writeup Rev.kr"
categories: ["Writeup"]
tags: ["Reverse", "Reversing.kr","trainning"]
#externalUrl: ""
date: 2022-02-10
draft: false
authors:
  - Fangyuan
---

# Reversing.kr practice Write-up 

## Easy Crack - 100pts

Initial analysis with [DiE](https://github.com/horsicq/Detect-It-Easy) , we have a PE32 file

![image](/images/Reversing.kr/image-0.png)

Open with IDA, at function `DialogFunc` have `sub_401080`, use winapi `GetDlgItemTextA` and `MessageBoxA`, take value from input to `String`, comapre then message.

```c
int __cdecl sub_401080(HWND hDlg)
{
  CHAR String[97]; // [esp+4h] [ebp-64h] BYREF
  __int16 v3; // [esp+65h] [ebp-3h]
  char v4; // [esp+67h] [ebp-1h]

  memset(String, 0, sizeof(String));
  v3 = 0;
  v4 = 0;
  GetDlgItemTextA(hDlg, 1000, String, 100);
  if ( String[1] != 97 || strncmp(&String[2], Str2, 2u) || strcmp(&String[4], aR3versing) || String[0] != 69 )
    return MessageBoxA(hDlg, aIncorrectPassw, Caption, 0x10u);
  MessageBoxA(hDlg, Text, Caption, 0x40u);
  return EndDialog(hDlg, 0);
}
```
The pass is :`Ea5yR3versing`

![image](/images/Reversing.kr/image-1.png)

## Easy Keygen - 100pts

Trong bài này ta cần phải tìm hiểu cách mà chương trình tạo ra `serial` từ chính `name` mà người dùng nhập vào, đó cũng là bản chất của `keygen (Key generator)`

In this chal, we need to analyse how program create `serial` from `name` that user input's, that how `keygen (Key generator)` work. 

Open program with IDA 32:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int v3; // ebp
  int i; // esi
  char v6; // [esp+Ch] [ebp-130h]
  char v7[2]; // [esp+Dh] [ebp-12Fh] BYREF
  char Var[100]; // [esp+10h] [ebp-12Ch] BYREF
  char Buffer[197]; // [esp+74h] [ebp-C8h] BYREF
  __int16 v10; // [esp+139h] [ebp-3h]
  char v11; // [esp+13Bh] [ebp-1h]

  memset(Var, 0, sizeof(Var));
  memset(Buffer, 0, sizeof(Buffer));
  v10 = 0;
  v11 = 0;
  v6 = 16;
  qmemcpy(v7, " 0", sizeof(v7));
  print(aInputName);
  scanf("%s", Var);
  v3 = 0;
  for ( i = 0; v3 < (int)strlen(Var); ++i )
  {
    if ( i >= 3 )
      i = 0;
    sprintf(Buffer, "%s%02X", Buffer, Var[v3++] ^ v7[i - 1]);
  }
  memset(Var, 0, sizeof(Var));
  print(aInputSerial);
  scanf("%s", Var);
  if ( !strcmp(Var, Buffer) )
    print(aCorrect);
  else
    print(aWrong);
  return 0;
}
```

Take `name` from user input then take each char in name `xor` with `v7`

```c
sprintf(Buffer, "%s%02X", Buffer, Var[v3++] ^ v7[i - 1]);
```

Initialise of array `v7` in asm

![image](https://user-images.githubusercontent.com/88520787/174272756-9d7d37eb-0201-4060-ac88-ea0e027e35f3.png)

`v7 = [0x10,0x20,0x30]`

Simple  reverse of `xor`.

```py
serial = "5B134977135E7D13"
b = bytes.fromhex(serial)
v7 = [0x10,0x20,0x30]
for i in range(8):
    print(chr(int(b[i])^v7[i%3]),end ="") #K3yg3nm3
```
`Name: K3yg3nm3` 

## Easy Unpack - 100pts

As the name of the program suggest, it have been `Packed`, which is a technique in reverse that they usually use to obfuscate or hide the code from normal viewing it.

![image](/images/Reversing.kr/image-2.png)

> There is a `EP(Entry Point)` in normal program, which is a Started Point, from then, program will be execute, in this situatian file is being packed, **EP** has been change.
 
> Depend on Packer, program will be packed on diffrent data sections, **EP** will decode data into original. After decoding completed, it start program with **EP** or also know as (Original-Entry-Point)`.

So now, we need to find the **OEP** of the chal, which is also the answer.

![image](/images/Reversing.kr/image-3.png)

Using PE-Editor, find current EP. After decrypt it jump to **OEP** to execute.

![image](/images/Reversing.kr/image-4.png)

`OEP:00401150`

## Easy ELF - 100pts

Not recommend using IDA for these challenge since, we can just 'f5' for psuedocode, instaed we shoulde practice ASM :))

Focus on this section, it check user input:

```c
_BOOL4 CHECK()
{
  if ( byte_804A021 != 49 )
    return 0;
  input ^= 0x34u;
  byte_804A022 ^= 0x32u;
  byte_804A023 ^= 0x88u;
  if ( byte_804A024 != 88 )
    return 0;
  if ( byte_804A025 )
    return 0;
  if ( byte_804A022 != 124 )
    return 0;
  if ( input == 120 )
    return byte_804A023 == -35;
  return 0;
}
```
Continue analyse.

![image](/images/Reversing.kr/image-5.png)

Rename data type and struct to understand easier.

```c
_BOOL4 CHECK()
{
  if ( input1 != 49 )
    return 0;
  input ^= 0x34u;
  input2 ^= 0x32u;
  input3 ^= 0x88u;
  if ( input4 != 88 )
    return 0;
  if ( input5 )
    return 0;
  if ( input2 != 124 )
    return 0;
  if ( input == 120 )
    return input3 == -35;
  return 0;
}
```
Rev time!!
```py
input = [0]*5
input[0] = 120^0x34
input[1] = 49
input[2] = 124^0x32
input[3] = (0xdd)^0x88
input[4] = 88
print("".join([chr(c) for c in input]))
```
Password: `L1NUX`

## Replace - 150pts

when debug, click `check` it got this error.

![image](https://user-images.githubusercontent.com/88520787/174285235-a266e0b8-f7fd-4793-bd35-51de2cf27808.png)

Try enter 1 number.

![image](https://user-images.githubusercontent.com/88520787/174285824-52cce0b2-f316-41e7-896f-c20f44e4d489.png)

Still at `40466F`,check in data:

![image](https://user-images.githubusercontent.com/88520787/174286024-9f1e4bab-6457-42cd-a779-c1a26409649c.png)

At line `call $+5`, set breakpoint and debug:

![image](https://user-images.githubusercontent.com/88520787/174287105-d55df6d0-6ef2-4f31-a03d-b654b4f0c9dc.png)

Terminate debug, run with input = 4567,  `dword_4084D0` change base on what input in, specificly input+2 and plus with `601605C7h`:

![image](https://user-images.githubusercontent.com/88520787/174287785-ea396c0c-5db8-469c-b9dd-2812ed211ac6.png)

Increase by 2 times before being push and call (at `inc eax` and `inc dword_4084D0`)


That means the error is due to not being able to find the correct offset to call, we need to calculate specifically to get the correct address. Use `Strings` tab.

![image](https://user-images.githubusercontent.com/88520787/174288099-8ca47fb5-3bd7-4138-b8b6-77c3e55e6bee.png)
![image](https://user-images.githubusercontent.com/88520787/174291594-50aa5fcd-cc30-4d07-8152-5bef9b53224d.png)

Our addr is `0x00401071`

Message when blank input is `0x601605CB`, but when enter `4567` it becomes `0x601617A2` which is `0x601605CB+ hex(4567)`

```
input + 2 + 0x601605C7 + 2 = 0x00401071
input = (0x00401071 - 2 - 2 - 0x601605C7) & 0xffffffff = 2687109798 // & 0xffffffff become positive
```
![image](https://user-images.githubusercontent.com/88520787/174293047-7aec64c1-d211-4992-a3f0-a90fdcc6520d.png)

`input = 2687109798`

## ImagePrc - 120pts

![image](/images/Reversing.kr/image-6.png)

Draw and check

Find `check`:
```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  int SystemMetrics; // eax
  HWND Window; // eax
  int v7; // [esp-1Ch] [ebp-64h]
  struct tagMSG Msg; // [esp+4h] [ebp-44h] BYREF
  WNDCLASSA WndClass; // [esp+20h] [ebp-28h] BYREF

  ::hInstance = hInstance;
  WndClass.cbClsExtra = 0;
  WndClass.cbWndExtra = 0;
  WndClass.hbrBackground = (HBRUSH)GetStockObject(0);
  WndClass.hCursor = LoadCursorA(0, (LPCSTR)0x7F00);
  WndClass.hInstance = hInstance;
  WndClass.hIcon = LoadIconA(0, (LPCSTR)0x7F00);
  WndClass.lpfnWndProc = sub_401130;
  WndClass.lpszClassName = lpWindowName;
  WndClass.lpszMenuName = 0;
  WndClass.style = 3;
  RegisterClassA(&WndClass);
  v7 = GetSystemMetrics(1) / 2 - 75;
  SystemMetrics = GetSystemMetrics(0);
  Window = CreateWindowExA(
             0,
             lpWindowName,
             lpWindowName,
             0xCA0000u,
             SystemMetrics / 2 - 100,
             v7,
             200,
             150,
             0,
             0,
             hInstance,
             0);
  ShowWindow(Window, 5);
  if ( !GetMessageA(&Msg, 0, 0, 0) )
    return Msg.wParam;
  do
  {
    TranslateMessage(&Msg);
    DispatchMessageA(&Msg);
  }
  while ( GetMessageA(&Msg, 0, 0, 0) );
  return Msg.wParam;
}
```
Check function `sub_401130` . 
```c
case 1u:
          DC = GetDC(hWnd);
          hbm = CreateCompatibleBitmap(DC, 200, 150);
          hdc = CreateCompatibleDC(DC);
          h = SelectObject(hdc, hbm);
          Rectangle(hdc, -5, -5, 205, 205);
          ReleaseDC(hWnd, DC);
          ::wParam = (WPARAM)CreateFontA(12, 0, 0, 0, 400, 0, 0, 0, 0x81u, 0, 0, 0, 0x12u, pszFaceName);
          dword_4084E0 = (int)CreateWindowExA(
                                0,
                                ClassName,
                                WindowName,
                                0x50000000u,
                                60,
                                85,
                                80,
                                28,
                                hWnd,
                                (HMENU)0x64,
                                hInstance,
                                0);
          SendMessageA((HWND)dword_4084E0, 0x30u, ::wParam, 0);
          return 0;
```

Function `CreateCompatibleBitmap()` with image size is `200x150`

```c
if ( wParam == 100 )
    {
      GetObjectA(hbm, 24, pv);
      memset(&bmi, 0, 0x28u);
      bmi.bmiHeader.biHeight = cLines;
      bmi.bmiHeader.biWidth = v16;
      bmi.bmiHeader.biSize = 40;
      bmi.bmiHeader.biPlanes = 1;
      bmi.bmiHeader.biBitCount = 24;
      bmi.bmiHeader.biCompression = 0;
      GetDIBits(hdc, (HBITMAP)hbm, 0, cLines, 0, &bmi, 0);
      v8 = operator new(bmi.bmiHeader.biSizeImage);
      GetDIBits(hdc, (HBITMAP)hbm, 0, cLines, v8, &bmi, 0);
      ResourceA = FindResourceA(0, (LPCSTR)101, (LPCSTR)0x18);
      Resource = LoadResource(0, ResourceA);
      v11 = LockResource(Resource);
      v12 = 0;
      v13 = v8;
      v14 = v11 - (_BYTE *)v8;
      while ( *v13 == v13[v14] )
      {
        ++v12;
        ++v13;
        if ( v12 >= 90000 )
        {
          sub_401500(v8);
          return 0;
        }
      }
      MessageBoxA(hWnd, Text, Caption, 0x30u);
      sub_401500(v8);
      return 0;
    }
```
Compare each `byte` with the `bitmap`, before cmp, the function uses `GetDIBits,GetDIBits,FindResourceA,LoadResource`.Using `ResourceHacker` for analyse data sections:

![image](/images/Reversing.kr/image-7.png)

To view it, we need file header that matches the bitmap header, we can go online and copy and replace it or create a bitmap file with paint (remember to adjust the resolution to 200x150 before saving):

![image](/images/Reversing.kr/image-8.png)

After save, open with Hxd:

![image](/images/Reversing.kr/image-9.png)

Copy data from ResourceHacker then save it.

![image](/images/Reversing.kr/image-10.png)
`Key: GOT`

## Music Player - 150pts

Readme file:
```
This MP3 Player is limited to 1 minutes.
You have to play more than one minute.

There are exist several 1-minute-check-routine.
After bypassing every check routine, you will see the perfect flag.
```

There is suppose to be `Msbox` but nothing seem right.

![image](/images/Reversing.kr/image-11.png)

Since the chal also provide the `.dll` file so we need to check the imported section.

![image](/images/Reversing.kr/image-12.png)

There is `WinAPI`, double click then use `xref` ('x' key) then check what it calls. 

![alt text](/images/Reversing.kr/image-13.png)

![alt text](/images/Reversing.kr/image-14.png)

Conditon to jmp here:

![alt text](/images/Reversing.kr/image-15.png)
if fail jmp to this block `Msbox fail`

Before we have `cmp eax, 60000` mean that cmp with `60000ms = 1p`, if greater dont jump and go to path `FAIL`, otherwise reeverse.

By this time, i know that we suppose to practice our patching skill, for faster patch, people suggest me using IDA Plugin called keypatch ,with combinations shortcuts Ctrl + Alt + K.change the command jl to jmp:

![alt text](/images/Reversing.kr/image-16.png)

![alt text](/images/Reversing.kr/image-17.png)

There is also another jump, so we need to modified it too.

![alt text](/images/Reversing.kr/image-18.png)

```call    ds:__vbaHresultCheckObj```

As above change it into `jmp` too.

![alt text](/images/Reversing.kr/image-19.png)

![alt text](/images/Reversing.kr/image-20.png)

Run again it should work.

## CSHOP - 120pts

For this chal, we gonna use [dnSpy](https://github.com/dnSpy/dnSpy) to analyse:

![alt text](/images/Reversing.kr/image-21.png)

Theo kinh nghiệm của mình code của bài này đã bị obfuscate, ban đầu mình nghĩ là sẽ unobfuscate trước sau đó phân tích sau, nhưng khi đọc sơ qua thì mình thấy có 1 chổ hơi bất ổn:

![alt text](/images/Reversing.kr/image-22.png)

![alt text](/images/Reversing.kr/image-23.png)

Resize the `button` (0,0):

![alt text](/images/Reversing.kr/image-24.png)

![alt text](/images/Reversing.kr/image-25.png)

Click then get flag.

![alt text](/images/Reversing.kr/image-26.png)

## Position - 160pts

![alt text](/images/Reversing.kr/image-27.png)

![alt text](/images/Reversing.kr/image-28.png)

Learning from the previous post (Musicplayer), this time I check the tab `import` and `string` first.

![alt text](/images/Reversing.kr/image-29.png)

There is `GetWinDowTextW`, xref for reference called it:

![alt text](/images/Reversing.kr/image-30.png)

![alt text](/images/Reversing.kr/image-31.png)

There are 2 vars to call and save `v50` and `v51`, in which `v50` , check `[a-z]` so I'm pretty sure this is the name, the rest is the serial, change it for easier view.

![alt text](/images/Reversing.kr/image-32.png)

Now let's checking names:

![alt text](/images/Reversing.kr/image-33.png)

Serial only have value 6,7,8 since first char is always +5, next char is +1

```c
c1 = (name[0] & 1) + 5;
    c2 = ((name[0] & 0x10) != 0) + 5;
    c3 = ((name[0] & 2) != 0) + 5;
    c4 = ((name[0] & 4) != 0) + 5;
    c5 = ((name[0] & 8) != 0) + 5;
    c4_ = (name[1] & 1) + 1;
    c3_ = ((name[1] & 0x10) != 0) + 1;
    c2_ = ((name[1] & 2) != 0) + 1;
    c1_ = ((name[1] & 4) != 0) + 1;
    c5_ = ((name[1] & 8) != 0) + 1;
    check += ((c1 + c1_)== 7 );
    check += ((c5 + c5_)== 6 );
    check += ((c3 + c3_)== 8 );
    check += ((c4 + c4_)== 7 );
    check += ((c2 + c2_)== 6 );
```
![alt text](/images/Reversing.kr/image-34.png)

Similar with the 3rd and last chars.

```c
c6 = (name[2] & 1) + 5;
    c7 = ((name[2] & 0x10) != 0) + 5;
    c8 = ((name[2] & 2) != 0) + 5;
    c9 = ((name[2] & 4) != 0) + 5;
    c10 = ((name[2] & 8) != 0) + 5;
    c9_ = (name[3] & 1) + 1;
    c8_ = ((name[3] & 0x10) != 0) + 1;
    c7_ = ((name[3] & 2) != 0) + 1;
    c6_ = ((name[3] & 4) != 0) + 1;
    c10_ = ((name[3] & 8) != 0) + 1;
    check += ((c6 + c6_)== 7 );
    check += ((c10 + c10_)== 7 );
    check += ((c8 + c8_)== 7 );
    check += ((c9 + c9_)== 7 );
    check += ((c7 + c7_)== 6 );
```

Wrap up:

```c
bool check(string name){
    int c1,c2,c3,c4,c5,c1_,c2_,c3_,c4_,c5_,c6,c7,c8,c9,c10,c6_,c7_,c8_,c9_,c10_;
    int check = 0;
    c1 = (name[0] & 1) + 5;
    c2 = ((name[0] & 0x10) != 0) + 5;
    c3 = ((name[0] & 2) != 0) + 5;
    c4 = ((name[0] & 4) != 0) + 5;
    c5 = ((name[0] & 8) != 0) + 5;
    c4_ = (name[1] & 1) + 1;
    c3_ = ((name[1] & 0x10) != 0) + 1;
    c2_ = ((name[1] & 2) != 0) + 1;
    c1_ = ((name[1] & 4) != 0) + 1;
    c5_ = ((name[1] & 8) != 0) + 1;
    // 5 so dau cua serial
    check += ((c1 + c1_)== 7 );
    check += ((c5 + c5_)== 6 );
    check += ((c3 + c3_)== 8 );
    check += ((c4 + c4_)== 7 );
    check += ((c2 + c2_)== 6 );
    c6 = (name[2] & 1) + 5;
    c7 = ((name[2] & 0x10) != 0) + 5;
    c8 = ((name[2] & 2) != 0) + 5;
    c9 = ((name[2] & 4) != 0) + 5;
    c10 = ((name[2] & 8) != 0) + 5;
    c9_ = (name[3] & 1) + 1;
    c8_ = ((name[3] & 0x10) != 0) + 1;
    c7_ = ((name[3] & 2) != 0) + 1;
    c6_ = ((name[3] & 4) != 0) + 1;
    c10_ = ((name[3] & 8) != 0) + 1;
    //5 so sau cua serial
    check += ((c6 + c6_)== 7 );
    check += ((c10 + c10_)== 7 );
    check += ((c8 + c8_)== 7 );
    check += ((c9 + c9_)== 7 );
    check += ((c7 + c7_)== 6 );
    return check ==10;
}
```
Bruteforce 3 first chars of pass , 26^3 

```c
#include <bits/stdc++.h>
using namespace std;
bool check(string name){
    int c1,c2,c3,c4,c5,c1_,c2_,c3_,c4_,c5_,c6,c7,c8,c9,c10,c6_,c7_,c8_,c9_,c10_;
    int check = 0;
    c1 = (name[0] & 1) + 5;
    c2 = ((name[0] & 0x10) != 0) + 5;
    c3 = ((name[0] & 2) != 0) + 5;
    c4 = ((name[0] & 4) != 0) + 5;
    c5 = ((name[0] & 8) != 0) + 5;
    c4_ = (name[1] & 1) + 1;
    c3_ = ((name[1] & 0x10) != 0) + 1;
    c2_ = ((name[1] & 2) != 0) + 1;
    c1_ = ((name[1] & 4) != 0) + 1;
    c5_ = ((name[1] & 8) != 0) + 1;
    // 5 so dau cua serial
    check += ((c1 + c1_)== 7 );
    check += ((c5 + c5_)== 6 );
    check += ((c3 + c3_)== 8 );
    check += ((c4 + c4_)== 7 );
    check += ((c2 + c2_)== 6 );
    c6 = (name[2] & 1) + 5;
    c7 = ((name[2] & 0x10) != 0) + 5;
    c8 = ((name[2] & 2) != 0) + 5;
    c9 = ((name[2] & 4) != 0) + 5;
    c10 = ((name[2] & 8) != 0) + 5;
    c9_ = (name[3] & 1) + 1;
    c8_ = ((name[3] & 0x10) != 0) + 1;
    c7_ = ((name[3] & 2) != 0) + 1;
    c6_ = ((name[3] & 4) != 0) + 1;
    c10_ = ((name[3] & 8) != 0) + 1;
    //5 so sau cua serial
    check += ((c6 + c6_)== 7 );
    check += ((c10 + c10_)== 7 );
    check += ((c8 + c8_)== 7 );
    check += ((c9 + c9_)== 7 );
    check += ((c7 + c7_)== 6 );
    return check ==10;
}
void brutePass(string name,int length,string set){
    if (name.size()==length) return;
    for (auto c:set){
        string temp = name+ c;
        if (check(temp) && temp[3]=='p'){
            cout<<temp<<endl;
            break;
        }
        brutePass(temp,length,set);
    }
}
int main(){
    string set = "abcdefghijklmnopqrstuvwxyz";
    brutePass("",4,set);
    return 0;
}
```

![alt text](/images/Reversing.kr/image-35.png)

Choose fisrt:

![alt text](/images/Reversing.kr/image-36.png)

## Direct3D FPS - 140pts

![alt text](/images/Reversing.kr/image-37.png)

![alt text](/images/Reversing.kr/image-38.png)

Traced it and saw that the `sub_4039C0` called:

```c
int *sub_4039C0()
{
  int *result; // eax

  result = &dword_409194;
  while ( *result != 1 )
  {
    result += 132;
    if ( (int)result >= (int)&unk_40F8B4 )
    {
      MessageBoxA(hWnd, aCkfkbulileEZf, "Game Clear!", 0x40u);
      return (int *)SendMessageA(hWnd, 2u, 0, 0);
    }
  }
  return result;
}
```
The msg `Game Clear` there is also this string attached

![alt text](/images/Reversing.kr/image-39.png)

Using xref, it was getting xored, this must be decrypted

![alt text](/images/Reversing.kr/image-40.png)

```c
int __thiscall sub_403400(void *this)
{
  int result; // eax
  int v2; // edx

  result = sub_403440(this);
  if ( result != -1 )
  {
    v2 = dword_409190[132 * result];
    if ( v2 > 0 )
    {
      dword_409190[132 * result] = v2 - 2;
    }
    else
    {
      dword_409194[132 * result] = 0;
      data[result] ^= byte_409184[528 * result];
    }
  }
  return result;
}
```
I change teh data name ,it take each char then xor with `byte_409184`, check `byte_409184+528` what do we have here. 

![alt text](/images/Reversing.kr/image-41.png)

Using the python in IDA and got the following result: (0x002D9184 is the location of byte_409184)

```
  Python>b = 0x002D9184 
  Python>get_bytes(b,1)
  b'\x00'
  Python>get_bytes(b+518,1)
  b'S'
  Python>b = 0x002D9184
  Python>get_bytes(b,1)
  b'\x00'
  Python>get_bytes(b+528,1)
  b'\x04'
  Python>get_bytes(b+528*2,1)
  b'\x08'
```
`byte_409184` gonna e an arrayfrom 0,4,8,12,16...then xor with the available data.

I wrote this script to get data and `byte_409184` then xor them together:

```py
data = 0x0407028 #data start address
j =0
for i in range(50):
    print(chr(int.from_bytes(get_bytes(data+i,1),"big")^j),end = "")
    j+=4
```
Use IDA's load script to run the py file:

![alt text](/images/Reversing.kr/image-42.png)

![alt text](/images/Reversing.kr/image-43.png)

## Multiplicative - 170pts

We have a jar file

Use `jadx` to decompile:

![alt text](/images/Reversing.kr/image-44.png)

![alt text](/images/Reversing.kr/image-45.png)

This problem uses multiplication before calculation, so pretty sure this is overflow.
Type `long` has 64 bits so the largest number will be 2^63-1, the next number will be -2^63, so we will calculate a reasonable value for it to return to 
-1536092243306511225

Convert -1536092243306511225 to unsigned number, we get 0xeaaeb43e477b8487

(0xeaaeb43e477b8487 + 2^64.n) will be a multiple of 26729, script:

```py
from ctypes import *
i = 0
while True:
    if ((2**64)*i + 0xeaaeb43e477b8487)%26729==0:
        print((2**64)*i + 0xeaaeb43e477b8487)
        break
    i+=1
print(c_int64(253087792599051741660295//26729))
```

Flag:
`-8978084842198767761`

## ransomware - 120pts

![alt text](/images/Reversing.kr/image-46.png)

By the name, the `file` must have been encrypted, so it cannot run:

![alt text](/images/Reversing.kr/image-47.png)

Test with random input, there is a change in the content of file:

![alt text](/images/Reversing.kr/image-48.png)

![alt text](/images/Reversing.kr/image-49.png)

File has been packed

![alt text](/images/Reversing.kr/image-50.png)
Use `CFF Explorer` to unpack it:

![alt text](/images/Reversing.kr/image-51.png)

The program used fopen to open a `file` named file, mode is `rb`, which means reading bytes from the given file

![alt text](/images/Reversing.kr/image-52.png)

After calling the file read command, the program will loop to get each byte of the file and then save it to `byte_5415B8`:

![alt text](/images/Reversing.kr/image-53.png)

Next section jump `loc_44A8A5`

![alt text](/images/Reversing.kr/image-54.png)

Through the debugging, I found that `[ebp+var_8]` will count from 0 to `[ebp+var_10]` (len of file), if smaller, then continue the loop, temporarily called `i` and `n`.

![alt text](/images/Reversing.kr/image-55.png)

There are 3 instructions `xor`, the first xor is  to clear edx, there is also `div` for `[ebp+var_C]` (length of the key from user), which `div` will use `eax ` divided by the source operand register, then the remainder stored in `edx`

```
movsx   edx, byte_44D370[edx]
```
byte_44D370 is the user entered key,

Then our bytes file is still `xor` with 0xFF, our encryption will be:

```c
byte[i] = byte[i]^key[i%len(key)]^0xFF
```
We dont know the `key` and `len(key)` so i try bruteforce but not work.

We `xor` the og file with `0xFF` first:

```py
b = bytearray(open('file', 'rb').read())
for i in range(len(b)):
    b[i] = b[i]^0xFF
open('file_new', 'wb').write(b)
```

Open `file_new` with HxD:

![alt text](/images/Reversing.kr/image-56.png)

A readable text that repeats many times, this is definitely the key, try entering it into the file `run.exe`:

![alt text](/images/Reversing.kr/image-57.png)


![alt text](/images/Reversing.kr/image-58.png)

Key seem right, but how can we run it now:

![alt text](/images/Reversing.kr/image-59.png)

Using DiE, I see this is a 32bits executable file and packed, unpacked and put into ida to try:v

![alt text](/images/Reversing.kr/image-60.png)

Flag: `Colle System`

## HateIntel - 150pts

![alt text](/images/Reversing.kr/image-61.png)

Run on `macOS`, however compiled with `gcc`:

![alt text](/images/Reversing.kr/image-62.png)

`macOS` use the architecture `ARM (arm architecture)` instead of `intel_x86,_x64` other chals, `ARM` usually writing all the commands in UPPERCASE. Function `main()`:

```c
int sub_2224()
{
  char __s[80]; // [sp+4h] [bp-5Ch] BYREF
  int v2; // [sp+54h] [bp-Ch]
  int v3; // [sp+58h] [bp-8h]
  int i; // [sp+5Ch] [bp-4h]

  v2 = 4;
  printf("Input key : ");
  scanf("%s", __s);
  v3 = strlen(__s);
  sub_232C(__s, v2);
  for ( i = 0; i < v3; ++i )
  {
    if ( __s[i] != byte_3004[i] )
    {
      puts("Wrong Key! ");
      return 0;
    }
  }
  puts("Correct Key! ");
  return 0;
}
```

The program takes the user's input , then call `sub_232C` (maybe encryption method) ,then compares it with the byteavailable data in the program:

![alt text](/images/Reversing.kr/image-63.png)

Check the method `encrypt`:

```c
signed __int32 __fastcall encrypt(signed __int32 result, int a2)
{
  char *__s; // [sp+4h] [bp-10h]
  int i; // [sp+8h] [bp-Ch]
  signed __int32 j; // [sp+Ch] [bp-8h]

  __s = (char *)result;
  for ( i = 0; i < a2; ++i )
  {
    for ( j = 0; ; ++j )
    {
      result = strlen(__s);
      if ( result <= j )
        break;
      __s[j] = sub_2494((unsigned __int8)__s[j], 1);
    }
  }
  return result;
}
```

Iterates through the string 4 times (a2 = 4), each time each character will be encrypt with the method `sub_2494`:

```c
int __fastcall sub_2494(unsigned __int8 a1, int a2)
{
  int v3; // [sp+8h] [bp-8h]
  int i; // [sp+Ch] [bp-4h]

  v3 = a1;
  for ( i = 0; i < a2; ++i )
  {
    v3 *= 2;
    if ( (v3 & 0x100) != 0 )
      v3 |= 1u;
  }
  return (unsigned __int8)v3;
}
```

Method `sub_2494` also has a loop, but a2 = 1, so we consider it as not having a loop, we focus on the logic, at `v3 |= 1u;` so this function will handle bit operations:

```c
int rotate(char c){
    c <<=1;
    if ( (c & 0x100) != 0 ) c |= 1u;
    return (unsigned __int8)c; // lấy 8 bits cuối
}
```

Shift 8 bits of the character to the left, take the first bit and add it to the end, or in other words `rotate bits`, when rotating 4 times, the first 4 bits become the last 4 bits and vice versa:

```py
b = [0x44, 0xF6, 0xF5, 0x57, 0xF5, 0xC6, 0x96, 0xB6, 0x56,0xF5, 0x14, 0x25, 0xD4, 0xF5, 0x96, 0xE6, 0x37, 0x47,0x27, 0x57, 0x36, 0x47, 0x96, 3, 0xE6, 0xF3, 0xA3,0x92]
for byte in b:
    last = byte>>4
    first = byte&0xF
    s = (first<<4) | last 
    print(chr(s),end = "") #Do_u_like_ARM_instructi0n?:)
```
Flag: `Do_u_like_ARM_instructi0n?:)`

## x64 Lotto - 140pts

![alt text](/images/Reversing.kr/image-64.png)

![alt text](/images/Reversing.kr/image-65.png)

Analyse with IDA:

```c
__int64 wmain()
{
  unsigned int v0; // eax
  __int64 i; // rbx
  char v2; // r8
  int v3; // edx
  __int64 k; // rcx
  _BYTE *v5; // rdx
  __int64 j; // rcx
  char v7; // al
  int v8; // ecx
  __int16 *v9; // rdx
  __int16 v10; // ax
  __int16 v11; // ax
  int n1; // [rsp+40h] [rbp-78h] BYREF
  int n2; // [rsp+44h] [rbp-74h] BYREF
  int n3; // [rsp+48h] [rbp-70h] BYREF
  int n4; // [rsp+4Ch] [rbp-6Ch] BYREF
  int n5; // [rsp+50h] [rbp-68h] BYREF
  int n6; // [rsp+54h] [rbp-64h] BYREF
  int v19[3]; // [rsp+58h] [rbp-60h]
  int v20; // [rsp+64h] [rbp-54h]
  int v21; // [rsp+68h] [rbp-50h]
  int v22; // [rsp+6Ch] [rbp-4Ch]
  __int16 v23[25]; // [rsp+70h] [rbp-48h] BYREF
  __int16 v24; // [rsp+A2h] [rbp-16h]

  n1 = 0;
  n2 = 0;
  n3 = 0;
  n4 = 0;
  n5 = 0;
  n6 = 0;
  v19[0] = 0;
  v19[1] = 0;
  v19[2] = 0;
  v20 = 0;
  v21 = 0;
  v22 = 0;
  v0 = time64(0i64);
  srand(v0);
  do
  {
    wprintf(L"\n\t\tL O T T O\t\t\n\n");
    wprintf(L"Input the number: ");
    wscanf_s(L"%d %d %d %d %d %d", &n1, &n2, &n3, &n4, &n5, &n6);
    wsystem(L"cls");
    Sleep(500u);
    for ( i = 0i64; i < 6; v19[i - 1] = rand() % 100 )
      ++i;
    v2 = 1;
    v3 = 0;
    k = 0i64;
    byte_7FF658B935F0 = 1;
    while ( v19[k] == *(&n1 + k * 4) )
    {
      ++k;
      ++v3;
      if ( k >= 6 )
        goto LABEL_9;
    }
    v2 = 0;
    byte_7FF658B935F0 = 0;
LABEL_9:
    ;
  }
  while ( v3 != 6 );
  v5 = byte;
  v23[1] = 92;
  v23[0] = 184;
  v23[2] = 139;
  v23[5] = 184;
  v23[3] = 107;
  j = 0i64;
  v23[4] = 66;
  v23[6] = 56;
  v23[7] = 237;
  v23[8] = 219;
  v23[9] = 91;
  v23[10] = 129;
  v23[11] = 41;
  v23[12] = 160;
  v23[13] = 126;
  v23[14] = 80;
  v23[15] = 140;
  v23[16] = 27;
  v23[17] = 134;
  v23[18] = 245;
  v23[19] = 2;
  v23[20] = 85;
  v23[21] = 33;
  v23[22] = 12;
  v23[23] = 14;
  v23[24] = 242;
  v24 = 0;
  do
  {
    v7 = byte[j - 1];
    j += 5i64;
    *(&v20 + j + 1) ^= (v7 - 12);
    *(&v21 + j) ^= (byte[j - 5] - 12);
    *(&v21 + j + 1) ^= (byte[j - 4] - 12);
    v23[j - 2] ^= (byte[j - 3] - 12);
    v23[j - 1] ^= (byte[j - 2] - 12);
  }
  while ( j < 25 );
  if ( v2 )
  {
    v8 = 0;
    v9 = v23;
    do
    {
      v10 = *v9++;
      v11 = v8++ + (v10 ^ 0xF);
      *(v9 - 1) = v11;
    }
    while ( v8 < 25 );
    v24 = 0;
    wprintf(L"%s\n", v23);
  }
  wprintf(L"\n", v5);
  return 1i64;
}
```

The program asks me to enter 6 numbers:

```c
wscanf_s(L"%d %d %d %d %d %d", &n1, &n2, &n3, &n4, &n5, &n6);
```
And then these 6 numbers will be compared with 6 randomly generated numbers:
```c
for ( i = 0i64; i < 6; v19[i - 1] = rand() % 100 )
      ++i;
```

Initialize the value and decrypt my password

```c
do
  {
    v7 = byte[j - 1];
    j += 5i64;
    *(&v20 + j + 1) ^= (v7 - 12);
    *(&v21 + j) ^= (byte[j - 5] - 12);
    *(&v21 + j + 1) ^= (byte[j - 4] - 12);
    v23[j - 2] ^= (byte[j - 3] - 12);
    v23[j - 1] ^= (byte[j - 2] - 12);
  }
  ```

Set breakpoint here to analyse the loop.

![alt text](/images/Reversing.kr/image-66.png)

Select Local windows debuggerand start debugging

After entering 6 random numbers, return to the debug screen:

![alt text](/images/Reversing.kr/image-67.png)

Here the program checks if all 6 numbers are correct, it uses the command `jnz`, if not 0 (ZF = 0) then it will jump to the input:

![alt text](/images/Reversing.kr/image-68.png)

Change ZeroFlag to 1:

![alt text](/images/Reversing.kr/image-69.png)

![alt text](/images/Reversing.kr/image-70.png)

After decrypting there is still one more condition:

![alt text](/images/Reversing.kr/image-71.png)

Set a breakpoint and do the same here:

![alt text](/images/Reversing.kr/image-72.png)

This time the program uses the command jz(jump if zero, ZF = 1), just need to change it in reverse compared to the command above:

![alt text](/images/Reversing.kr/image-73.png)

Here the program will print something that looks like a password

![alt text](/images/Reversing.kr/image-74.png)

![alt text](/images/Reversing.kr/image-75.png)

Password: `from_GHL2_-_!`

## AutoHotKey1 - 130pts

![alt text](/images/Reversing.kr/image-76.png)

File packed with UPX:

![alt text](/images/Reversing.kr/image-77.png)

Mình thử dùng UPX 3.96 để unpack file này ra nhưng sau khi chạy thì nó hiện thông báo lỗi: 

![alt text](/images/Reversing.kr/image-78.png)

I tried searching in the string `Exe corrupted` and xref and there are 2 functions that use it:

![alt text](/images/Reversing.kr/image-79.png)

![alt text](/images/Reversing.kr/image-80.png)

Based on the known offset, I used x32dbg to debug this file and traced it to this part:

![alt text](/images/Reversing.kr/image-81.png)

![alt text](/images/Reversing.kr/image-82.png)

`je` will jump past this test, so I set a breakpoint there and adjust `ZeroFlag = 1`:

After passing, when running for a while, you will see the MD5 `DecryptKey` appear:

![alt text](/images/Reversing.kr/image-83.png)

```220226394582d7117410e3c021748c2a```

Decrypt MD5 with online tool ( https://md5decrypt.net/).

![alt text](/images/Reversing.kr/image-84.png)

Find the rest

![alt text](/images/Reversing.kr/image-85.png)

Try setting a breakpoint, step into is the same:

![alt text](/images/Reversing.kr/image-86.png)

![alt text](/images/Reversing.kr/image-87.png)

Here is the comparison `pwd hash`, imilar, decrypt md5:
```54593f6b9413fc4ff2b4dec2da337806```
Result

![alt text](/images/Reversing.kr/image-88.png)

Password: `isolated pawn`

## CSHARP - 160pts

![alt text](/images/Reversing.kr/image-89.png)

Because it's Csharp, I use dnSpy64

![alt text](/images/Reversing.kr/image-90.png)

After the file receives its input, it will convert it to base64 bytes, and then run through this Invoke function to check:

![alt text](/images/Reversing.kr/image-91.png)

Set a breakpoint at the function call and debug:

![alt text](/images/Reversing.kr/image-92.png)

Press F11 to step into the function:

![alt text](/images/Reversing.kr/image-93.png)

Continue F11:

![alt text](/images/Reversing.kr/image-94.png)

Only focus on the return of the function:

![alt text](/images/Reversing.kr/image-95.png)

Step into:

![alt text](/images/Reversing.kr/image-96.png)

In `RuntimeMethodHandle` there is something running with it, but i couldn't do static analysis before:

![alt text](/images/Reversing.kr/image-97.png)

Step into:

![alt text](/images/Reversing.kr/image-98.png)

Copy to python and edit:

```py
from base64 import b64decode
flag = [0]*12
flag[0] = 16 ^ 74

flag[3] = 51 ^ 70

flag[1] = 17 ^ 87

flag[2] = 33 ^ 77

flag[11] = 17 ^ 44

flag[8] = 144 ^ 241

flag[4] = 68 ^ 29

flag[5] = 102 ^ 49

flag[9] = 181 ^ 226

flag[7] = 160 ^ 238

flag[10] = 238 ^ 163

flag[6] = 51 ^ 117
print(b64decode("".join([chr(i) for i in flag])).decode())
#dYnaaMic
```

![alt text](/images/Reversing.kr/image-99.png)

Password: `dYnaaMic`

## Twist1 - 190pts
From source and write up and explain by others, I was able to do this chal.

![alt text](/images/Reversing.kr/image-100.png)

![alt text](/images/Reversing.kr/image-101.png)

Normal input chal, let analyse with IDA:

![alt text](/images/Reversing.kr/image-102.png)

Very few functions and no OEP found so I think this is a packed file somehow

When running it shows an error like this:

![alt text](/images/Reversing.kr/image-103.png)

The program stops at the command pop ss:

![alt text](/images/Reversing.kr/image-104.png)

Reference [pop ss](https://daehee87.tistory.com/23):

> `pop ss` will execute the next command and block the current command until the next command is executed.

In addition, when I debug, I see a loop section where `loc_407063`, when running this section, the code sections appear one after another below, this will be the decryot section, so I set a breakpoint there `0040706F` to get the entire complete code.
 
![alt text](/images/Reversing.kr/image-105.png)

There are a lot of common anti-debug techniques.

Switching to x32dbg, after the code was decrypted, I noticed something `mov eax,dword ptr fs:[30]` strange:

![alt text](/images/Reversing.kr/image-106.png)

This is a antidebug technique, found on [stackoverflow](https://stackoverflow.com/questions/14496730/mov-eax-large-fs30h). 

This means that eax is set to point to a point in the PEB structure in the process.

![alt text](/images/Reversing.kr/image-107.png)

`eax` value now.

![alt text](/images/Reversing.kr/image-108.png)

Addr of PEB is `0x332000`:

![alt text](/images/Reversing.kr/image-109.png)

`edx` is 0, since `ecx` got xor each other,then store with value 0x28, the result then xor with 0x30 (result = 0x18) and then added directly to eax or the address of PEB. In other words, It pointed to `addrss of PEB + 0x18`.

The PEB architecture is configured slightly differently in different x32 and x64 versions. In this case, we are looking at a 32bit, trong trường hợp này, edx will point to `ProcessHeap (PEB + 0x18)`.

Inside `twist1.40709F`, ProcessHeap is added by 0xC and compare with `2`:

![alt text](/images/Reversing.kr/image-110.png)

```

+0x000 Entry : _HEAP_ENTRY

+0x008 Signature : Uint4B

+0x00c Flags : Uint4B

+0x010 ForceFlags : Uint4B

+0x014 VirtualMemoryThreshold : Uint4B

+0x018 SegmentReverse : Uint4B

+0x01c SegmentCommit : Uint4B

+0x020 DecommitFreeBlockThreshold : Uint4B
```

Smae at `004070D5` will also be a ProcessHeap + 0x10 to access ForceFlags and verify.

![alt text](/images/Reversing.kr/image-111.png)

To bypass , you need to set the `ecx` register to have a value equal to `ebx`:

![alt text](/images/Reversing.kr/image-112.png)

Next

![alt text](/images/Reversing.kr/image-113.png)

![alt text](/images/Reversing.kr/image-114.png)

This time, the ptr ePPEBdx- 0x10 return to PEB, then the program uses  + 0xC, it will point to `_PEB_LDR_DATA`. `_EB_LDR_DATA + 0x10` to use `InInitializationOrderLinks`(based on LDR_DATA_TABLE_ENTRY to search).

Ldr performs a check to see if it is debugging by repeatedly comparing it to 0xEEFEEEFE or 0xABABABAB to see if the debugger has filled the unused part of the heap with 0xABABABAB or 0xEEFEEEFE, specifically it compares 0x1F4 times:

![alt text](/images/Reversing.kr/image-115.png)

At `407183` there is still a loop, set a breakpoint at nop to exit the loop

![alt text](/images/Reversing.kr/image-116.png)

Then the program jump to `40157C` which is likely the entrypoint, by then the program is completely unpacked:

![alt text](/images/Reversing.kr/image-117.png)

When run ,at `40129B` it got this error like this:

![alt text](/images/Reversing.kr/image-118.png)

![alt text](/images/Reversing.kr/image-119.png)

Try jump to the next address `40129D`:

![alt text](/images/Reversing.kr/image-120.png)

Input field:

![alt text](/images/Reversing.kr/image-121.png)

![alt text](/images/Reversing.kr/image-122.png)

`twis1.401240` is check function.
Go inside, we can see our input store

![alt text](/images/Reversing.kr/image-123.png)

Input is at:

![alt text](/images/Reversing.kr/image-124.png)

![alt text](/images/Reversing.kr/image-125.png)

Here we will find al = 0x77^0x35 = “B”; (3rd character)

Debug

![alt text](/images/Reversing.kr/image-126.png)

Trap, bypass:

![alt text](/images/Reversing.kr/image-127.png)

Do the same with the remaining characters and you will get the corresponding string.
Input: `RIBENA`.

## PEpassword - 150pts

![alt text](/images/Reversing.kr/image-128.png)

![alt text](/images/Reversing.kr/image-129.png)

![alt text](/images/Reversing.kr/image-130.png)

### Original.exe:

![alt text](/images/Reversing.kr/image-131.png)

![alt text](/images/Reversing.kr/image-132.png)

The Original file will be the file before packing, basically it xor 2 arrays together, and this is when I set a breakpoint to see its value before printing:

![alt text](/images/Reversing.kr/image-133.png)
Punch of ?

### Packed.exe:

![alt text](/images/Reversing.kr/image-134.png)

![alt text](/images/Reversing.kr/image-135.png)

Because it is a packed file, at first the file requires a password. I guess it will use this password to decrypt the file into the original file. 

After debugging, I found the place where the file gets my input:

![alt text](/images/Reversing.kr/image-136.png)

Mình đã đổi tên cho dễ hiểu, tạm thời mình bỏ qua đoạn nhập pass word và đi thẳng đến đoạn nó lấy password xử lí bằng cách pass qua các lệnh `jz` bằng cách mod giá trị `ZF` và trace tới hàm process:

Bypassing it through `jz` by modifying the value `ZF` then trace

![alt text](/images/Reversing.kr/image-137.png)

Input store in `ebx` and `eax` before processing, after processing the return is `eax` while `ebx` is const.

![alt text](/images/Reversing.kr/image-138.png)

Return `eax` use for decoding 0x401004 and the value is 0x5a5a7e05

And for one reason, after xor eax with `.text` in packed, that segment will become the original segment, so I use HxD to trace

Original.exe:

![alt text](/images/Reversing.kr/image-139.png)

Packed.exe:

![alt text](/images/Reversing.kr/image-140.png)

`eax = Packed(0x014cec81) ^ Original(0xb6e62e17) = 0xb7aac296`

We have `eax`, `ebx` is const so we can brutefroce to find ebx:

```c
#include <iostream>
using namespace std;

unsigned int  rol(unsigned int x, int count) {
	unsigned int num1 = (x << count) & 4294967295;
	unsigned int num2 = x >> (32 - count);

	return num1 | num2;
}
unsigned int ror(unsigned int x, int count) {
	return rol(x, 32 - count);
}
//funtion : internet

int main() {
	for (unsigned int i = 0; i < 0xffffffff; i++) {
		unsigned int ebx = i;
		unsigned int eax = 0xb7aac296;
		unsigned int al = eax & 0xff;
		ebx = rol(ebx, al % 32);
		eax = eax ^ ebx;
		unsigned int bh = (ebx & 0xffff) >> 8;
		eax = ror(eax, bh % 32);
		if (eax == 0x5a5a7e05)
			printf("ebx : 0x%08x\n", i);
	}
	return 0;
}
```
```
ebx : 0xa1beee22
ebx : 0xc263a2cb
```
There are 2 reasonable values, try `eax` and `ebx` at `0040921F`:

![alt text](/images/Reversing.kr/image-141.png)

Finished.

![alt text](/images/Reversing.kr/image-142.png)

Password: `From_GHL2_!!`

## WindowKernel - 220pts

### Overview

![alt text](/images/Reversing.kr/image-143.png)

![alt text](/images/Reversing.kr/image-144.png)

![alt text](/images/Reversing.kr/image-145.png)

![alt text](/images/Reversing.kr/image-146.png)

![alt text](/images/Reversing.kr/image-147.png)


### Approach

![alt text](/images/Reversing.kr/image-148.png)

```c=
INT_PTR __stdcall DialogFunc(HWND hWnd, UINT a2, WPARAM a3, LPARAM a4)
{
  if ( a2 == 272 )
  {
    SetDlgItemTextW(hWnd, 1001, L"Wait.. ");
    SetTimer(hWnd, 0x464u, 0x3E8u, 0);
    return 1;
  }
  if ( a2 != 273 )
  {
    if ( a2 == 275 )
    {
      KillTimer(hWnd, 0x464u);
      sub_401310();
      return 1;
    }
    return 0;
  }
  if ( (unsigned __int16)a3 == 2 )
  {
    SetDlgItemTextW(hWnd, 1001, L"Wait.. ");
    sub_401490();
    EndDialog(hWnd, 2);
    return 1;
  }
  if ( (unsigned __int16)a3 == 1002 )
  {
    if ( HIWORD(a3) == 1024 )
    {
      Sleep(0x1F4u);
      return 1;
    }
    return 1;
  }
  if ( (unsigned __int16)a3 != 1003 )
    return 0;
  sub_401110(hWnd);
  return 1;
}
```

In `sub_401110(hWnd);` there is a string `Correct!`

```c=
HWND __thiscall sub_401110(HWND hDlg)
{
  HWND result; // eax
  HWND v3; // eax
  HWND v4; // eax
  HWND DlgItem; // eax
  WCHAR String[256]; // [esp+8h] [ebp-204h] BYREF

  GetDlgItemTextW(hDlg, 1003, String, 512);
  if ( lstrcmpW(String, L"Enable") )
  {
    result = (HWND)lstrcmpW(String, L"Check");
    if ( !result )
    {
      if ( sub_401280(0x2000) == 1 )
        MessageBoxW(hDlg, L"Correct!", L"Reversing.Kr", 0x40u);
      else
        MessageBoxW(hDlg, L"Wrong", L"Reversing.Kr", 0x10u);
      SetDlgItemTextW(hDlg, 1002, &word_4021F0);
      DlgItem = GetDlgItem(hDlg, 1002);
      EnableWindow(DlgItem, 0);
      return (HWND)SetDlgItemTextW(hDlg, 1003, L"Enable");
    }
  }
  else if ( sub_401280(4096) )
  {
    v3 = GetDlgItem(hDlg, 1002);
    EnableWindow(v3, 1);
    SetDlgItemTextW(hDlg, 1003, L"Check");
    SetDlgItemTextW(hDlg, 1002, &word_4021F0);
    v4 = GetDlgItem(hDlg, 1002);
    return SetFocus(v4);
  }
  else
  {
    return (HWND)MessageBoxW(hDlg, L"Device Error", L"Reversing.Kr", 0x10u);
  }
  return result;
}
```

Focus on `sub_401280(0x2000) == 1`, if condition true it will return "Correct!":

```c=
int __usercall sub_401280@<eax>(HWND a1@<edi>, DWORD dwIoControlCode)
{
  HANDLE FileW; // esi
  DWORD BytesReturned; // [esp+4h] [ebp-8h] BYREF
  int OutBuffer; // [esp+8h] [ebp-4h] BYREF

  FileW = CreateFileW(L"\\\\.\\RevKr", 0xC0000000, 0, 0, 3u, 0, 0);
  if ( FileW == (HANDLE)-1 )
  {
    MessageBoxW(a1, L"[Error] CreateFile", L"Reversing.Kr", 0x10u);
    return 0;
  }
  else if ( DeviceIoControl(FileW, dwIoControlCode, 0, 0, &OutBuffer, 4u, &BytesReturned, 0) )
  {
    CloseHandle(FileW);
    return OutBuffer;
  }
  else
  {
    MessageBoxW(a1, L"[Error] DeviceIoControl", L"Reversing.Kr", 0x10u);
    return 0;
  }
}
```
Here is the part where it creates the file and returns 1, I pay attention to this part:

```c
DeviceIoControl(FileW, dwIoControlCode, 0, 0, &OutBuffer, 4u, &BytesReturned, 0)
```
Basically it stands for Device In Out Control, go back and check the file `WinKer.sys`:

```c=
NTSTATUS __stdcall DriverEntry(_DRIVER_OBJECT *DriverObject, PUNICODE_STRING RegistryPath)
{
  int v3; // edi
  PDEVICE_OBJECT v4; // ecx
  char *v5; // et1
  char *v6; // et1
  char *v7; // et1
  char v8; // al
  struct _KDPC *v9; // esi
  char *v10; // et1
  struct _UNICODE_STRING DestinationString; // [esp+Ch] [ebp-134h] BYREF
  union _LARGE_INTEGER Interval; // [esp+14h] [ebp-12Ch] BYREF
  PDEVICE_OBJECT DeviceObject; // [esp+1Ch] [ebp-124h] BYREF
  PVOID P; // [esp+20h] [ebp-120h]
  CCHAR Number[4]; // [esp+24h] [ebp-11Ch]
  struct _OSVERSIONINFOW VersionInformation; // [esp+28h] [ebp-118h] BYREF

  DbgSetDebugFilterState(0x65u, 3u, 1u);
  DbgPrint("Driver Load!! \n");
  DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1131C;
  dword_13030 = 0;
  VersionInformation.dwOSVersionInfoSize = 276;
  if ( RtlGetVersion(&VersionInformation) )
  {
    MajorVersion = VersionInformation.dwMajorVersion;
    MinorVersion = VersionInformation.dwMinorVersion;
  }
  else
  {
    PsGetVersion(&MajorVersion, &MinorVersion, 0, 0);
  }
  RtlInitUnicodeString(&DestinationString, "\\");
  P = (PVOID)IoCreateDevice(DriverObject, 4u, &DestinationString, 0x22u, 0, 0, &DeviceObject);
  if ( (int)P >= 0 )
  {
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\RevKr");
    v3 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
    if ( v3 >= 0 )
    {
      v4 = DeviceObject;
      DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)sub_11288;
      DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)sub_112F8;
      DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)sub_112F8;
      *(_DWORD *)v4->DeviceExtension = 0;
      SystemArgument2 = DeviceObject->DeviceExtension;
      *(_DWORD *)SystemArgument2 = DeviceObject;
      v5 = *(char **)&KeNumberProcessors;
      ::P = ExAllocatePool(NonPagedPool, 4 * *v5);
      KeInitializeDpc(&DeviceObject->Dpc, sub_11266, DeviceObject);
      v6 = *(char **)&KeNumberProcessors;
      P = ExAllocatePool(NonPagedPool, 32 * *v6);
      if ( P )
      {
        v7 = *(char **)&KeNumberProcessors;
        Interval.QuadPart = -10000000i64;
        v8 = *v7;
        Number[0] = 0;
        if ( v8 > 0 )
        {
          do
          {
            v9 = (struct _KDPC *)((char *)P + 32 * Number[0]);
            KeInitializeDpc(v9, sub_113E8, 0);
            KeSetTargetProcessorDpc(v9, Number[0]);
            KeInsertQueueDpc(v9, 0, 0);
            KeDelayExecutionThread(0, 0, &Interval);
            v10 = *(char **)&KeNumberProcessors;
            ++Number[0];
          }
          while ( Number[0] < *v10 );
        }
        ExFreePoolWithTag(P, 0);
      }
      return 0;
    }
    else
    {
      IoDeleteDevice(DriverObject->DeviceObject);
      return v3;
    }
  }
  else
  {
    DbgPrint("IoCreateDevice Error\n");
    return (NTSTATUS)P;
  }
}
```

At `DbgPrint("IoCreateDevice Error\n");` file create `IoCreateDevice` then check and send to file `WindowKernel`.

```c=
int __stdcall sub_111DC(char a1)
{
  int result; // eax
  bool v2; // zf

  result = 1;
  if ( dword_1300C != 1 )
  {
    switch ( dword_13034 )
    {
      case 0:
      case 2:
      case 4:
      case 6:
        goto LABEL_3;
      case 1:
        v2 = a1 == -91;
        goto LABEL_6;
      case 3:
        v2 = a1 == -110;
        goto LABEL_6;
      case 5:
        v2 = a1 == -107;
LABEL_6:
        if ( !v2 )
          goto LABEL_7;
LABEL_3:
        ++dword_13034;
        break;
      case 7:
        if ( a1 == -80 )
          dword_13034 = 100;
        else
LABEL_7:
          dword_1300C = 1;
        break;
      default:
        result = sub_11156(a1);
        break;
    }
  }
  return result;
}
```

```c=
int __stdcall sub_11156(char a1)
{
  int result; // eax
  bool v2; // zf
  char v3; // [esp+8h] [ebp+8h]

  v3 = a1 ^ 0x12;
  result = dword_13034 - 100;
  switch ( dword_13034 )
  {
    case 'd':
    case 'f':
    case 'h':
    case 'j':
      goto LABEL_2;
    case 'e':
      v2 = v3 == -78;
      goto LABEL_4;
    case 'g':
      v2 = v3 == -123;
      goto LABEL_4;
    case 'i':
      v2 = v3 == -93;
LABEL_4:
      if ( !v2 )
        goto LABEL_5;
LABEL_2:
      ++dword_13034;
      break;
    case 'k':
      if ( v3 == -122 )
        dword_13034 = 200;
      else
LABEL_5:
        dword_1300C = 1;
      break;
    default:
      result = sub_110D0(v3);
      break;
  }
  return result;
}
```

```c=
int __stdcall sub_110D0(char a1)
{
  int result; // eax
  char v2; // cl
  bool v3; // zf

  result = dword_13034 - 200;
  v2 = a1 ^ 5;
  switch ( dword_13034 )
  {
    case 200:
    case 202:
    case 204:
    case 206:
      goto LABEL_2;
    case 201:
      v3 = v2 == -76;
      goto LABEL_4;
    case 203:
    case 205:
      v3 = v2 == -113;
LABEL_4:
      if ( v3 )
        goto LABEL_2;
      goto LABEL_10;
    case 207:
      if ( v2 != -78 )
        goto LABEL_10;
      dword_13024 = 1;
LABEL_2:
      ++dword_13034;
      break;
    case 208:
      dword_13024 = 0;
LABEL_10:
      dword_1300C = 1;
      break;
    default:
      return result;
  }
  return result;
}
```

All three of these functions share the same variable count `dword_13024` and loop through begin to end.

Back to the first function, the count variable starts from 0 => the first check function, next set `count = 100` and goes to the second function `count-100` and uses it => consider the input is divided into 3 segments and checked by 3 functions.


```c=
void __stdcall sub_11266(_KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
  char v4; // al

  v4 = READ_PORT_UCHAR((PUCHAR)0x60);
  first(v4);
}
```

It receives signal from API `READ_PORT_UCHAR` , if you look it up on the internet it will receive char from port 60 and return ` scancodes`.

`scancodes-keys map table` [here](https://wiki.osdev.org/PS/2_Keyboard).

First 4 characters.

```c=
int __stdcall first(char a1)
{
  int result; // eax
  bool v2; // zf

  result = 1;
  if ( dword_1300C != 1 )
  {
    switch ( count )
    {
      case 0:
      case 2:
      case 4:
      case 6:
        goto LABEL_3;
      case 1:
        v2 = a1 == (char)0xA5;                  // K realeased (phím K)
        goto LABEL_6;
      case 3:
        v2 = a1 == (char)0x92;                  // E realeased
        goto LABEL_6;
      case 5:
        v2 = a1 == (char)0x95;                  // Y realeased
LABEL_6:
        if ( !v2 )
          goto LABEL_7;
LABEL_3:
        ++count;
        break;
      case 7:
        if ( a1 == (char)0xB0 )                 // B realeased
          count = 100;
        else
LABEL_7:
          dword_1300C = 1;
        break;
      default:
        result = second(a1);
        break;
    }
  }
  return result;
}
```
Similar

```c=
int __stdcall second(char a1)
{
  int result; // eax
  bool v2; // zf
  char v3; // [esp+8h] [ebp+8h]

  v3 = a1 ^ 0x12;
  result = count - 100;
  switch ( count )
  {
    case 'd':
    case 'f':
    case 'h':
    case 'j':
      goto LABEL_2;
    case 'e':
      v2 = v3 == (char)0xB2;                    // 0x12^0xB2 = 0xA0 => D realeased
      goto LABEL_4;
    case 'g':
      v2 = v3 == (char)0x85;                    // 0x12^0x85 = 0x97 => I realeased
      goto LABEL_4;
    case 'i':
      v2 = v3 == (char)0xA3;                    // 0x12^0xA3 = 0xB1 => N realeased
LABEL_4:
      if ( !v2 )
        goto LABEL_5;
LABEL_2:
      ++count;
      break;
    case 'k':
      if ( v3 == (char)0x86 )                   // 0x12^0x86 = 0x94 => T realeased
        count = 200;
      else
LABEL_5:
        dword_1300C = 1;
      break;
    default:
      result = last(v3);
      break;
  }
  return result;
}
```
```c=
int __stdcall last(char a1)
{
  int result; // eax
  char v2; // cl
  bool v3; // zf

  result = count - 200;
  v2 = a1 ^ 5;
  switch ( count )
  {
    case 200:
    case 202:
    case 204:
    case 206:
      goto LABEL_2;
    case 201:
      v3 = v2 == (char)0xB4;                    // 0xB4^0x12^5 = 0xA3 => T
      goto LABEL_4;
    case 203:                                   // 0x8F^0x12^5 = 0x98 => O realeased
    case 205:                                   // 0x8F^0x12^5 = 0x98 => O realeased
      v3 = v2 == (char)0x8F;
LABEL_4:
      if ( v3 )
        goto LABEL_2;
      goto LABEL_10;
    case 207:
      if ( v2 != (char)0xB2 )                   // 0xB2^0x12^5 = 0xA5 => K realeased
        goto LABEL_10;
      dword_13024 = 1;
LABEL_2:
      ++count;
      break;
    case 208:
      dword_13024 = 0;
LABEL_10:
      dword_1300C = 1;
      break;
    default:
      return result;
  }
  return result;
}
```

Following the instructions in the readme.txt file, key:`keybdinthook`

