
int * FUN_08021c50(int *param_1,undefined4 param_2,int param_3,int param_4)

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
  undefined1 auStack_30 [20];
  
  *param_1 = (int)(param_1 + 2);
  local_38 = auStack_30;
  iStack_34 = 0;
  param_1[1] = 0;
  *(undefined1 *)(param_1 + 2) = 0;
  FUN_08021aee(&local_38,param_3,param_4);
  puVar5 = local_38;
  uVar4 = (param_4 - param_3) * 2;
  puVar6 = local_38 + iStack_34;
  iVar1 = thunk_FUN_08008466(uVar4);
  while( true ) {
    uVar7 = FUN_0801f9b8(param_2,iVar1,puVar5,uVar4);
    uVar2 = (uint)uVar7;
    if (uVar4 <= uVar2) {
      uVar4 = uVar2 + 1;
      if (iVar1 != 0) {
        thunk_FUN_080249c4(iVar1,(int)((ulonglong)uVar7 >> 0x20),uVar2);
      }
      iVar1 = thunk_FUN_08008466(uVar4);
      uVar2 = FUN_0801f9b8(param_2,iVar1,puVar5,uVar4);
    }
    FUN_08021c28(param_1,iVar1,uVar2);
    iVar3 = FUN_08005ea0(puVar5);
    if (puVar6 == puVar5 + iVar3) break;
    puVar5 = puVar5 + iVar3 + 1;
    FUN_08017ede(param_1,0);
  }
  if (iVar1 != 0) {
    thunk_FUN_080249c4(iVar1);
  }
  FUN_08006cec(&local_38);
  return param_1;
}

