
void FUN_0801eb48(undefined4 *param_1,uint param_2,undefined4 param_3)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  uint local_14;
  undefined4 uStack_10;
  
  puVar3 = param_1;
  local_14 = param_2;
  uStack_10 = param_3;
  uVar1 = FUN_0801eac4();
  if (uVar1 < local_14) {
    uVar2 = FUN_0801e990(param_1,&local_14,uVar1,local_14,puVar3);
    FUN_0801ea32(uVar2,*param_1,param_1[1] + 1);
    FUN_0801e9cc(param_1);
    *param_1 = uVar2;
    param_1[2] = local_14;
  }
  return;
}

