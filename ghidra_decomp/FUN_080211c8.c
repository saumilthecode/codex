
undefined4 FUN_080211c8(int *param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  
  iVar1 = FUN_080210e4(param_2,param_4);
  if (iVar1 == 0) {
LAB_080211da:
    uVar2 = 1;
  }
  else {
    while ((uint *)param_1[1] != (uint *)*param_1) {
      uVar3 = *(uint *)*param_1;
      if ((uVar3 - 0xd800 < 0x800) || (param_3 < uVar3)) {
        return 2;
      }
      iVar1 = FUN_08020cac(param_2);
      if (iVar1 == 0) goto LAB_080211da;
      *param_1 = *param_1 + 4;
    }
    uVar2 = 0;
  }
  return uVar2;
}

