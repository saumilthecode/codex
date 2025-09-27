
uint * FUN_0800b674(int param_1,uint *param_2,uint *param_3,undefined1 param_4,undefined1 *param_5)

{
  undefined1 uVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  
  if (*(char *)(param_1 + 0xc) == '\0') {
    for (; param_2 < param_3; param_2 = param_2 + 1) {
      uVar3 = FUN_08025928(*param_2);
      bVar4 = uVar3 != 0xffffffff;
      if (bVar4) {
        uVar3 = uVar3 & 0xff;
      }
      uVar1 = (char)uVar3;
      if (!bVar4) {
        uVar1 = param_4;
      }
      *param_5 = uVar1;
      param_5 = param_5 + 1;
    }
  }
  else {
    while (param_2 < param_3) {
      if (*param_2 < 0x80) {
        uVar1 = *(undefined1 *)(*param_2 + param_1 + 0xd);
      }
      else {
        iVar2 = FUN_08025928();
        uVar1 = param_4;
        if (iVar2 != -1) {
          uVar1 = (char)iVar2;
        }
      }
      *param_5 = uVar1;
      param_2 = param_2 + 1;
      param_5 = param_5 + 1;
    }
  }
  return param_3;
}

