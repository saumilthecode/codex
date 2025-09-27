
void FUN_08019bbe(int param_1,undefined4 param_2,int *param_3,int *param_4,int param_5,int param_6)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  
  uVar2 = *(uint *)(param_1 + 0xc) & 0xb0;
  param_5 = param_5 - param_6;
  if (uVar2 == 0x20) {
    if (param_6 != 0) {
      FUN_080269c0(param_3,param_4,param_6);
    }
    if (param_5 == 0) {
      return;
    }
    FUN_080269cc(param_3 + param_6,param_2,param_5,param_4);
    return;
  }
  if (uVar2 == 0x10) {
    uVar1 = FUN_08018e8c(param_1 + 0x6c);
    iVar5 = FUN_0800e0b2(uVar1,0x2d);
    iVar3 = *param_4;
    if (iVar5 != iVar3) {
      iVar5 = FUN_0800e0b2(uVar1,0x2b);
      iVar3 = *param_4;
      if (iVar5 != iVar3) {
        iVar5 = FUN_0800e0b2(uVar1,0x30);
        if (((iVar5 == *param_4) && (1 < param_6)) &&
           ((iVar5 = FUN_0800e0b2(uVar1,0x78), iVar5 == param_4[1] ||
            (iVar5 = FUN_0800e0b2(uVar1,0x58), iVar5 == param_4[1])))) {
          *param_3 = *param_4;
          param_3[1] = param_4[1];
          iVar5 = 2;
          piVar4 = param_3 + 2;
          goto LAB_08019c02;
        }
        goto LAB_08019bfe;
      }
    }
    piVar4 = param_3 + 1;
    *param_3 = iVar3;
    iVar5 = 1;
  }
  else {
LAB_08019bfe:
    iVar5 = 0;
    piVar4 = param_3;
  }
LAB_08019c02:
  if (param_5 != 0) {
    FUN_080269cc(piVar4,param_2,param_5);
  }
  if (param_6 - iVar5 == 0) {
    return;
  }
  FUN_080269c0(piVar4 + param_5,param_4 + iVar5,param_6 - iVar5,param_4);
  return;
}

