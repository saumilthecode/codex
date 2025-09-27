
void FUN_0801157c(int param_1,undefined4 param_2,byte *param_3,byte *param_4,int param_5,int param_6
                 )

{
  undefined4 uVar1;
  byte bVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  
  uVar3 = *(uint *)(param_1 + 0xc) & 0xb0;
  param_5 = param_5 - param_6;
  if (uVar3 == 0x20) {
    if (param_6 != 0) {
      FUN_08028666(param_3,param_4,param_6);
    }
    if (param_5 == 0) {
      return;
    }
    FUN_08026922(param_3 + param_6,param_2,param_5,param_4);
    return;
  }
  if (uVar3 == 0x10) {
    uVar1 = FUN_0801126c(param_1 + 0x6c);
    uVar3 = FUN_08010ce2(uVar1,0x2d);
    bVar2 = *param_4;
    if (uVar3 != bVar2) {
      uVar3 = FUN_08010ce2(uVar1,0x2b);
      bVar2 = *param_4;
      if (uVar3 != bVar2) {
        uVar3 = FUN_08010ce2(uVar1,0x30);
        if (((*param_4 == uVar3) && (1 < param_6)) &&
           ((uVar3 = FUN_08010ce2(uVar1,0x78), param_4[1] == uVar3 ||
            (uVar3 = FUN_08010ce2(uVar1,0x58), param_4[1] == uVar3)))) {
          *param_3 = *param_4;
          param_3[1] = param_4[1];
          iVar5 = 2;
          pbVar4 = param_3 + 2;
          goto LAB_080115be;
        }
        goto LAB_080115ba;
      }
    }
    pbVar4 = param_3 + 1;
    *param_3 = bVar2;
    iVar5 = 1;
  }
  else {
LAB_080115ba:
    iVar5 = 0;
    pbVar4 = param_3;
  }
LAB_080115be:
  if (param_5 != 0) {
    FUN_08026922(pbVar4,param_2,param_5);
  }
  if (param_6 - iVar5 == 0) {
    return;
  }
  FUN_08028666(pbVar4 + param_5,param_4 + iVar5,param_6 - iVar5,param_4);
  return;
}

