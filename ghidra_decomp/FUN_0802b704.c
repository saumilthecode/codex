
undefined4 FUN_0802b704(int param_1,int param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  iVar5 = param_2 + -2;
  if (DAT_0802b784 == 0) {
    iVar3 = DAT_0802b78c - DAT_0802b788 >> 3;
    iVar4 = DAT_0802b788;
    param_2 = iVar3;
LAB_0802b72c:
    iVar5 = FUN_0802b67a(iVar4,param_2,iVar5,iVar3,param_1,param_2,param_3);
    if (iVar5 != 0) {
      uVar6 = FUN_0802b668(iVar5,iVar5);
      iVar5 = (int)((ulonglong)uVar6 >> 0x20);
      iVar4 = *(int *)(iVar5 + 4);
      *(int *)(param_1 + 0x48) = (int)uVar6;
      if (iVar4 == 1) {
        iVar5 = 0;
        uVar1 = 5;
      }
      else {
        piVar2 = (int *)(iVar5 + 4);
        if (-1 < iVar4) {
          piVar2 = (int *)FUN_0802b668();
        }
        *(int **)(param_1 + 0x4c) = piVar2;
        *(uint *)(param_1 + 0x50) = (uint)(-1 >= iVar4);
        if (*piVar2 < 0) {
          iVar5 = FUN_0802b6dc((uint)(*piVar2 << 4) >> 0x1c);
          if (iVar5 == 0) {
            uVar1 = 9;
          }
          else {
            uVar1 = 0;
          }
        }
        else {
          iVar5 = FUN_0802b668();
          uVar1 = 0;
        }
      }
      goto LAB_0802b71c;
    }
  }
  else {
    iVar4 = iVar5;
    iVar3 = DAT_0802b784;
    if (iVar5 != 0) goto LAB_0802b72c;
  }
  iVar5 = 0;
  uVar1 = 9;
LAB_0802b71c:
  *(int *)(param_1 + 0x10) = iVar5;
  return uVar1;
}

