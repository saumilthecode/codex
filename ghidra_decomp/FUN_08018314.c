
bool FUN_08018314(int *param_1,int param_2,undefined4 *param_3)

{
  bool bVar1;
  int *local_10;
  int local_c;
  
  local_10 = param_1;
  local_c = param_2;
  (**(code **)(*param_1 + 0x14))(&local_10,param_1,param_2);
  if (local_c == param_3[1]) {
    bVar1 = local_10 == (int *)*param_3;
  }
  else {
    bVar1 = false;
  }
  return bVar1;
}

