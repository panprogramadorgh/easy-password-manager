#include "file.c"
#include "input.c"

int main()
{
  char password[MAX_PASSWD_NAME];

  if (getpasswd(password, "pass4", 1) != 1)
    return EXIT_FAILURE;
  printf("%s\n", password);

  return EXIT_SUCCESS;
}