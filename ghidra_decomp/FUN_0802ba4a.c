
int FUN_0802ba4a(code *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined1 auStack_258 [16];
  code *local_248;
  undefined4 local_200;
  undefined4 local_1fc;
  undefined4 uStack_1f8;
  undefined4 uStack_1f4;
  undefined4 uStack_1f0;
  undefined4 local_1ec;
  undefined4 uStack_1e8;
  undefined4 uStack_1e4;
  undefined4 uStack_1e0;
  undefined4 local_1dc;
  undefined4 uStack_1d8;
  undefined4 uStack_1d4;
  undefined4 uStack_1d0;
  undefined4 local_1cc;
  undefined4 uStack_1c8;
  undefined4 uStack_1c4;
  undefined4 local_1c0;
  
  *(undefined4 *)(param_3 + 0x40) = *(undefined4 *)(param_3 + 0x3c);
  local_1fc = *(undefined4 *)(param_3 + 4);
  uStack_1f8 = *(undefined4 *)(param_3 + 8);
  uStack_1f4 = *(undefined4 *)(param_3 + 0xc);
  uStack_1f0 = *(undefined4 *)(param_3 + 0x10);
  local_1ec = *(undefined4 *)(param_3 + 0x14);
  uStack_1e8 = *(undefined4 *)(param_3 + 0x18);
  uStack_1e4 = *(undefined4 *)(param_3 + 0x1c);
  uStack_1e0 = *(undefined4 *)(param_3 + 0x20);
  local_1dc = *(undefined4 *)(param_3 + 0x24);
  uStack_1d8 = *(undefined4 *)(param_3 + 0x28);
  uStack_1d4 = *(undefined4 *)(param_3 + 0x2c);
  uStack_1d0 = *(undefined4 *)(param_3 + 0x30);
  local_1cc = *(undefined4 *)(param_3 + 0x34);
  uStack_1c8 = *(undefined4 *)(param_3 + 0x38);
  uStack_1c4 = *(undefined4 *)(param_3 + 0x3c);
  local_1c0 = *(undefined4 *)(param_3 + 0x40);
  local_200 = 0xffffffff;
  do {
    iVar1 = FUN_0802b704(auStack_258,local_1c0);
    if (iVar1 != 0) break;
    FUN_0802ba32(&local_200,0xc,auStack_258);
    iVar1 = (*param_1)(&local_200,param_2);
    if (iVar1 != 0) break;
    iVar1 = (*local_248)(8,auStack_258,&local_200);
    if (iVar1 == 5) goto LAB_0802baae;
  } while (iVar1 != 9);
  iVar1 = 9;
LAB_0802baae:
  FUN_0802b790(&local_200);
  return iVar1;
}

