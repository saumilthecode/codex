
bool FUN_08007dce(char *param_1)

{
  if ((((*param_1 == 'G') && (param_1[1] == 'N')) && (param_1[2] == 'U')) &&
     (((param_1[3] == 'C' && (param_1[4] == 'C')) && ((param_1[5] == '+' && (param_1[6] == '+'))))))
  {
    return (byte)param_1[7] < 2;
  }
  return false;
}

