
int FUN_08021e4a(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                undefined4 param_5)

{
  int iVar1;
  int iVar2;
  undefined1 *puVar3;
  undefined1 *puVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  undefined1 *local_50;
  int local_4c;
  undefined1 auStack_48 [16];
  undefined1 *local_38;
  int iStack_34;
  undefined1 auStack_30 [20];
  
  local_50 = auStack_48;
  local_4c = 0;
  FUN_08021aee(&local_50);
  local_38 = auStack_30;
  iStack_34 = 0;
  FUN_08021aee(&local_38,param_4,param_5);
  puVar5 = local_50 + local_4c;
  puVar4 = local_38 + iStack_34;
  puVar3 = local_38;
  puVar6 = local_50;
  do {
    iVar1 = FUN_0801f9a2(param_1,puVar6,puVar3);
    if (iVar1 != 0) {
LAB_08021eaa:
      FUN_08006cec(&local_38);
      FUN_08006cec(&local_50);
      return iVar1;
    }
    iVar1 = FUN_08005ea0(puVar6);
    iVar2 = FUN_08005ea0(puVar3);
    puVar3 = puVar3 + iVar2;
    if (puVar5 == puVar6 + iVar1) {
      iVar1 = (int)puVar4 - (int)puVar3;
      if (iVar1 != 0) {
        iVar1 = -1;
      }
      goto LAB_08021eaa;
    }
    if (puVar4 == puVar3) {
      iVar1 = 1;
      goto LAB_08021eaa;
    }
    puVar6 = puVar6 + iVar1 + 1;
    puVar3 = puVar3 + 1;
  } while( true );
}

