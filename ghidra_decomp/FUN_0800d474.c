
int * FUN_0800d474(int param_1,undefined4 param_2,uint param_3)

{
  int *piVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined8 uVar5;
  undefined4 uVar6;
  
  uVar5 = CONCAT44(param_2,param_1);
  if (0xfffffffU - *(int *)(param_1 + 4) < param_3) {
    uVar5 = FUN_08010502(DAT_0800d498);
  }
  uVar3 = (undefined4)((ulonglong)uVar5 >> 0x20);
  piVar1 = (int *)uVar5;
  iVar4 = piVar1[1];
  uVar6 = uVar3;
  uVar2 = FUN_0801eac4();
  if (uVar2 < param_3 + iVar4) {
    FUN_0801ead6(piVar1,iVar4,0,uVar3,param_3,uVar6);
  }
  else if (param_3 != 0) {
    FUN_0801ea32(*piVar1 + iVar4 * 4,uVar3,param_3);
  }
  FUN_0801e978(piVar1,param_3 + iVar4);
  return piVar1;
}

