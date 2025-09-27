
undefined4 FUN_08029360(int param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if ((param_3 & 3) != 0) {
    param_2 = FUN_0802902c(param_1,param_2,*(undefined4 *)(DAT_0802940c + ((param_3 & 3) - 1) * 4),0
                           ,param_4);
  }
  param_3 = (int)param_3 >> 2;
  if (param_3 != 0) {
    puVar4 = *(undefined4 **)(param_1 + 0x1c);
    if (puVar4 == (undefined4 *)0x0) {
      puVar4 = (undefined4 *)FUN_080249b4(0x10);
      *(undefined4 **)(param_1 + 0x1c) = puVar4;
      puVar1 = puVar4;
      if (puVar4 == (undefined4 *)0x0) {
        puVar1 = (undefined4 *)FUN_08028754(DAT_08029414,0x1b3,0,DAT_08029410);
      }
      puVar1[1] = 0;
      puVar1[2] = 0;
      *puVar1 = 0;
      puVar1[3] = 0;
    }
    puVar1 = (undefined4 *)puVar4[2];
    if ((undefined4 *)puVar4[2] == (undefined4 *)0x0) {
      puVar1 = (undefined4 *)FUN_080291e4(param_1,0x271);
      puVar4[2] = puVar1;
      *puVar1 = 0;
    }
    do {
      puVar4 = puVar1;
      uVar3 = param_3 & 1;
      param_3 = (int)param_3 >> 1;
      uVar2 = param_2;
      if (uVar3 != 0) {
        uVar2 = FUN_08029210(param_1,param_2,puVar4);
        FUN_08028fe8(param_1,param_2);
        if (param_3 == 0) {
          return uVar2;
        }
      }
      param_2 = uVar2;
      puVar1 = (undefined4 *)*puVar4;
      if ((undefined4 *)*puVar4 == (undefined4 *)0x0) {
        puVar1 = (undefined4 *)FUN_08029210(param_1,puVar4,puVar4);
        *puVar4 = puVar1;
        *puVar1 = 0;
      }
    } while( true );
  }
  return param_2;
}

