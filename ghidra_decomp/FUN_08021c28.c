
int * FUN_08021c28(int param_1,undefined4 param_2,uint param_3)

{
  uint uVar1;
  int *piVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  undefined8 uVar6;
  undefined4 uVar7;
  
  uVar6 = CONCAT44(param_2,param_1);
  if (0x3fffffffU - *(int *)(param_1 + 4) < param_3) {
    uVar6 = FUN_08010502(DAT_08021c4c);
  }
  uVar3 = (undefined4)((ulonglong)uVar6 >> 0x20);
  piVar2 = (int *)uVar6;
  iVar5 = piVar2[1];
  uVar4 = param_3 + iVar5;
  uVar7 = uVar3;
  uVar1 = FUN_08017e26();
  if (uVar1 < uVar4) {
    FUN_08017e38(piVar2,iVar5,0,uVar3,param_3,uVar7);
  }
  else if (param_3 != 0) {
    FUN_08017d6c(*piVar2 + iVar5,uVar3,param_3);
  }
  piVar2[1] = uVar4;
  *(undefined1 *)(*piVar2 + uVar4) = 0;
  return piVar2;
}

