Compile for debugging with:  g++ -g login.cpp -o login

Start LLDB: LLDB ./login

Set breakpoints: 

    breakpoint set --line 125

Set args and run:

    run -k testusername testpassword
   

print memory layout:

    memory read &v.password
    memory read &v.canary
    memory read &v.good_username
    memory read &v.good_password
    memory read &v.username

to check for equality of values:

    p (int)strcmp(v.goodcanary, v.canary)
    p (int)strcmp(v.username, v.good_username)
    p (int)strcmp(v.password, v.good_password)

To Test Execution:

    LLDB ./login
    breakpoint set --line 161
    run -k mjk30 c(%%%%%%%%%%%%%%%%%%%%%%%%%%%%%mjk30(%%%%%%%%%%%%%%%%%%(c
    p (int)strcmp(v.username, v.good_username)
    p (int)strcmp(v.password, v.good_password)
    p v.goodcanary == v.canary

Okay characters: 0-9, A-Z, a-z
Characters that get removed: ()
Strange Characters: Anything else

Useful for checking mem:

    memory read &v.password
    memory read &v.good_password
    memory read &v.goodcanary
    memory read &v.canary
    memory read &v.good_username
    memory read &v.username

To Confirm:
run -k mjk30 a(%%%%%%%%%%%%%%%%%%%%%%%%%%%%%mjk30(%%%%%%%%%%%%%%%%%%(a

Solution: 
./login -k $(sed -n 1p a3a.txt) $(sed -n 2p a3a.txt)
./login -k mjk30 a(%%%%%%%%%%%%%%%%%%%%%%%%%%%%%mjk30(%%%%%%%%%%%%%%%%%%(a