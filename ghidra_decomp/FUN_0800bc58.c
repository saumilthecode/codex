
void FUN_0800bc58(undefined4 *param_1,int *param_2)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  int local_14;
  
  puVar1 = param_1 + 2;
  *param_1 = puVar1;
  iVar3 = *param_2;
  iVar2 = param_2[1];
  local_14 = (iVar2 << 2) >> 2;
  if (0xc < (uint)(iVar2 * 4)) {
    puVar1 = (undefined4 *)FUN_0801e990(param_1,&local_14,0,puVar1,param_1);
    *param_1 = puVar1;
    param_1[2] = local_14;
  }
  FUN_0801eaac(puVar1,iVar3,iVar3 + iVar2 * 4);
  FUN_0801e978(param_1,local_14);
  return;
}

