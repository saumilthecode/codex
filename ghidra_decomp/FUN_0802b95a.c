
void FUN_0802b95a(int param_1,int param_2)

{
  code *pcVar1;
  int iVar2;
  code *UNRECOVERED_JUMPTABLE;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_1 + 0xc);
  *(undefined4 *)(param_2 + 0x40) = *(undefined4 *)(param_1 + 0x14);
  if (iVar2 != 0) {
    FUN_0802b824(param_1,param_2,1);
LAB_0802b96e:
                    /* WARNING: Subroutine does not return */
    FUN_080249a4();
  }
  pcVar1 = *(code **)(param_1 + 0x10);
  iVar2 = (*pcVar1)(2,param_1,param_2);
  if (iVar2 != 7) {
    if (iVar2 != 8) goto LAB_0802b96e;
    FUN_0802b7ea(param_1,param_2);
  }
  FUN_0802b7e8(0,*(undefined4 *)(param_2 + 0x40));
  UNRECOVERED_JUMPTABLE = (code *)0x802b99b;
  uVar3 = FUN_080069b0(param_2 + 4);
  iVar2 = (int)((ulonglong)uVar3 >> 0x20);
  if (*(int *)((int)uVar3 + 0xc) != 0) {
    *(undefined4 *)(iVar2 + 0x40) = *(undefined4 *)(iVar2 + 0x3c);
    FUN_0802b824((int)uVar3,iVar2,0,pcVar1);
    return;
  }
  FUN_0802b8e4();
                    /* WARNING: Could not recover jumptable at 0x0802b9b4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(9);
  return;
}

