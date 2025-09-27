
int FUN_080269dc(undefined4 param_1,int param_2,uint param_3)

{
  char *pcVar1;
  uint uVar2;
  int local_1c;
  uint uStack_18;
  
  local_1c = 0;
  if (param_3 != 0) {
    uStack_18 = param_3;
    pcVar1 = (char *)FUN_0802a998(*DAT_08026a2c,param_1,1,&local_1c,param_1);
    uVar2 = FUN_08005ea0();
    if (uVar2 < param_3) {
      FUN_08028656(param_2,pcVar1);
      if (local_1c != 0) {
        return local_1c;
      }
      if (*pcVar1 != '\0') {
        return 0;
      }
      return 0x16;
    }
    FUN_08028666(param_2,pcVar1,param_3 - 1);
    *(undefined1 *)(param_2 + (param_3 - 1)) = 0;
  }
  return 0x22;
}

