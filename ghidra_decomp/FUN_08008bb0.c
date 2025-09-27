
void FUN_08008bb0(int param_1,int *param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  piVar1 = DAT_08008c40;
  DataMemoryBarrier(0x1b);
  piVar4 = DAT_08008c44;
  if ((-1 < *DAT_08008c40 << 0x1f) &&
     (iVar2 = FUN_0801f0da(DAT_08008c40), piVar4 = DAT_08008c44, iVar2 != 0)) {
    FUN_0801f0f2(piVar1);
    piVar4 = DAT_08008c44;
  }
  do {
    iVar6 = *piVar4;
    iVar2 = param_3;
    if (iVar6 == 0) {
      param_3 = -1;
LAB_08008bf4:
      iVar6 = *(int *)(param_1 + 0xc);
      if (*(int *)(iVar6 + iVar2 * 4) == 0) {
        iVar5 = param_2[1];
        param_2[1] = iVar5 + 1;
        if (param_3 != -1) {
          iVar5 = iVar5 + 2;
        }
        *(int **)(iVar6 + iVar2 * 4) = param_2;
        if (param_3 != -1) {
          param_2[1] = iVar5;
          *(int **)(iVar6 + param_3 * 4) = param_2;
        }
      }
      else if (param_2 != (int *)0x0) {
                    /* WARNING: Could not recover jumptable at 0x08008c08. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)(*param_2 + 4))(param_2);
        return;
      }
      return;
    }
    uVar7 = FUN_08008a40(iVar6);
    uVar3 = *(undefined4 *)((int)((ulonglong)uVar7 >> 0x20) + 4);
    if ((int)uVar7 == param_3) {
      param_3 = FUN_08008a40(uVar3);
      goto LAB_08008bf4;
    }
    uVar7 = FUN_08008a40(uVar3);
    if ((int)uVar7 == param_3) {
      iVar2 = FUN_08008a40(iVar6);
      goto LAB_08008bf4;
    }
    piVar4 = (int *)((int)((ulonglong)uVar7 >> 0x20) + 8);
  } while( true );
}

