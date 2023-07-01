Compile for debugging with:  g++ -g login.cpp -o login

Start LLDB: LLDB ./login

Set breakpoints: 

    breakpoint set --line 99

Set args and run:

    run -j testusername testpassword

    Sol'n:

    run 

print memory layout:

    memory read &v.password
    memory read &v.canary
    memory read &v.good_username
    memory read &v.good_password
    memory read &v.username

to check for equality of strings:

    p (int)strcmp(v.goodcanary, v.canary)
    p (int)strcmp(v.username, v.good_username)
    p (int)strcmp(v.password, v.good_password)

To Test Execution:

    LLDB ./login
    breakpoint set --line 92
    run -j mjk3000000000000000000000 testpassword1234567890120000AF2Tmjk3000000000000000000000testpassword123456789012
    p (int)strcmp(v.password, v.good_password)
    p (int)strcmp(v.username, v.good_username)
    p v.goodcanary == v.canary

Useful for checking mem:

    memory read &v.password
    memory read &v.good_password
    memory read &v.goodcanary
    memory read &v.canary
    memory read &v.good_username
    memory read &v.username

To Confirm:
./login -j mjk3000000000000000000000 testpassword1234567890120000AF2Tmjk3000000000000000000000testpassword123456789012
./login -j $(sed -n 1p a2a.txt) $(sed -n 2p a2a.txt)