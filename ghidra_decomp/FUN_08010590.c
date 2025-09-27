
uint FUN_08010590(int param_1,int param_2)

{
  uint uVar1;
  int extraout_r1;
  int iVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x7c);
  iVar2 = param_2;
  if (piVar3 == (int *)0x0) {
    FUN_080104f6();
    iVar2 = extraout_r1;
  }
  if ((char)piVar3[7] == '\0') {
    FUN_0800b34a(piVar3);
                    /* WARNING: Could not recover jumptable at 0x080105b2. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (**(code **)(*piVar3 + 0x18))(piVar3,param_2);
    return uVar1;
  }
  return (uint)*(byte *)((int)piVar3 + iVar2 + 0x1d);
}

