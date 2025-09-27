
int * FUN_0800d49c(int *param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  undefined8 uVar7;
  undefined1 *local_38;
  int iStack_34;
  undefined1 auStack_30 [16];
  
  *param_1 = (int)(param_1 + 2);
  local_38 = auStack_30;
  param_1[1] = 0;
  param_1[2] = 0;
  iStack_34 = 0;
  FUN_0800d2de(&local_38,param_3,param_4);
  puVar5 = local_38;
  puVar6 = local_38 + iStack_34 * 4;
  uVar4 = param_4 - param_3 >> 1;
  if (DAT_0800d55c < (uint)(param_4 - param_3)) {
    iVar1 = -1;
  }
  else {
    iVar1 = uVar4 << 2;
  }
  iVar1 = thunk_FUN_08008466(iVar1);
  while( true ) {
    uVar7 = FUN_0801f9d8(param_2,iVar1,puVar5,uVar4);
    uVar2 = (uint)uVar7;
    if (uVar4 <= uVar2) {
      uVar4 = uVar2 + 1;
      if (iVar1 != 0) {
        thunk_FUN_080249c4(iVar1,(int)((ulonglong)uVar7 >> 0x20),uVar2);
      }
      if (uVar4 < 0x1fffffff) {
        iVar1 = uVar4 * 4;
      }
      else {
        iVar1 = -1;
      }
      iVar1 = thunk_FUN_08008466(iVar1);
      uVar2 = FUN_0801f9d8(param_2,iVar1,puVar5,uVar4);
    }
    FUN_0800d474(param_1,iVar1,uVar2);
    iVar3 = FUN_0802698c(puVar5);
    if (puVar6 == puVar5 + iVar3 * 4) break;
    puVar5 = puVar5 + iVar3 * 4 + 4;
    FUN_0801eb7e(param_1,0);
  }
  if (iVar1 != 0) {
    thunk_FUN_080249c4(iVar1);
  }
  FUN_0801e9cc(&local_38);
  return param_1;
}

