
undefined4 *
FUN_08023dc2(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,undefined4 param_9,
            char param_10,char param_11)

{
  char cVar1;
  char cVar2;
  uint *puVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 local_48;
  undefined4 uStack_44;
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined1 local_38;
  char local_37;
  char local_36;
  undefined1 local_35;
  undefined4 local_34;
  undefined4 uStack_30;
  undefined4 local_2c;
  
  cVar2 = param_11;
  cVar1 = param_10;
  puVar3 = param_8;
  iVar5 = param_7;
  local_40 = param_3;
  uStack_3c = param_4;
  uVar4 = FUN_0801126c(param_7 + 0x6c);
  *puVar3 = 0;
  local_38 = FUN_08010ce2(uVar4,0x25);
  if (cVar2 == '\0') {
    local_37 = cVar1;
    local_36 = cVar2;
  }
  else {
    local_35 = 0;
    local_37 = cVar2;
    local_36 = cVar1;
  }
  local_34 = 0;
  uStack_30 = 0;
  local_2c = 0;
  FUN_08022d94(&local_48,param_2,local_40,uStack_3c,param_5,param_6,iVar5,puVar3,param_9,&local_38,
               &local_34);
  local_40 = local_48;
  uStack_3c = uStack_44;
  FUN_0801fbe0(&local_34,param_9);
  iVar5 = FUN_08012eba(&local_40,&param_5);
  if (iVar5 != 0) {
    *puVar3 = *puVar3 | 2;
  }
  *param_1 = local_40;
  param_1[1] = uStack_3c;
  return param_1;
}

