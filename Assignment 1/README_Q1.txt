Compile for debugging with:  g++ -g login.cpp -o login

Start LLDB: LLDB ./login

Set breakpoints: 

    breakpoint set --line 49

Set args and run:

    run -i testusername testpassword

    Sol'n:

    run -i mjk3000000000000 000000000

print memory layout:

    memory read &v.check_failed

To Test Execution:

    LLDB ./login
    breakpoint set --line 49
    run -i mjk3000000000000 000000000
    memory read &v.check_failed


To Confirm:
./login -i mjk3000000000000 000000000
./login -i $(sed -n 1p a1a.txt) $(sed -n 2p a1a.txt)