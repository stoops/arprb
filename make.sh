gcc                                   \
  -D_FORTIFY_SOURCE=2                 \
  -Wno-parentheses                    \
  -Wno-maybe-uninitialized            \
  -Wall -Wextra -Werror               \
  -Wformat-security                   \
  -fstack-protector-all               \
  -pie -fPIE -Wl,-pie                 \
  -Wl,-z,defs -Wl,-z,now -Wl,-z,relro \
  -O2 -o $1 $1.c
