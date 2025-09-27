
int FUN_0800d67c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
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
  FUN_0800d2de(&local_50);
  local_38 = auStack_30;
  iStack_34 = 0;
  FUN_0800d2de(&local_38,param_4,param_5);
  puVar5 = local_50 + local_4c * 4;
  puVar4 = local_38 + iStack_34 * 4;
  puVar3 = local_38;
  puVar6 = local_50;
  do {
    iVar1 = FUN_0801f9c2(param_1,puVar6,puVar3);
    if (iVar1 != 0) {
LAB_0800d6e2:
      FUN_0801e9cc(&local_38);
      FUN_0801e9cc(&local_50);
      return iVar1;
    }
    iVar1 = FUN_0802698c(puVar6);
    iVar2 = FUN_0802698c(puVar3);
    puVar3 = puVar3 + iVar2 * 4;
    if (puVar5 == puVar6 + iVar1 * 4) {
      iVar1 = (int)puVar4 - (int)puVar3;
      if (iVar1 != 0) {
        iVar1 = -1;
      }
      goto LAB_0800d6e2;
    }
    if (puVar4 == puVar3) {
      iVar1 = 1;
      goto LAB_0800d6e2;
    }
    puVar6 = puVar6 + iVar1 * 4 + 4;
    puVar3 = puVar3 + 4;
  } while( true );
}

