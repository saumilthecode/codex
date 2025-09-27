
uint FUN_08010ce2(int *param_1,int param_2)

{
  uint uVar1;
  
  if ((char)param_1[7] == '\0') {
    FUN_0800b34a();
                    /* WARNING: Could not recover jumptable at 0x08010cfc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (**(code **)(*param_1 + 0x18))(param_1,param_2);
    return uVar1;
  }
  return (uint)*(byte *)((int)param_1 + param_2 + 0x1d);
}

