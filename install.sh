#!/bin/bash

# Checks a list of given packages
check_linux_packages()
{
	# Checking the installed packages and seeing the given error code
	#dpkg --status $1 &> /dev/null
	dpkg --status | grep -w $1 &> /dev/null
	# If the error code is 0 then the package is installed, otherwise
	if [ $? -eq 0 ];
	then
		printf "Package $1 exists\n"
	else
		printf "I don't have that package, I'll try to install it\n"
		apt install $1
	fi
}

check_python_packages() 
{
	pip3 show $1 &> /dev/null
	#pip3 list | cut -d ' ' -f 1 | grep -w $1

	# If the package is present, then tell the 
	if [ $? -eq 0 ];
	then
		printf "Package $1 exists\n"
	else
		printf "I will try to install the package: $1\n"
		pip3 install $1
	fi
}

# Checking if the exact given package is firstly installed or not and if it is then skip it, if not then try to install it
# Test the program by trying to input a package

linux_packages=("python3-pip" "python3")
python_packages=("dpkt" "scapy" "matplotlib" "subprocess")
# for loop which accesses the created array and then invokes the check packages function
printf "Checking for Linux packages\n"
for linux_package in "${linux_packages[@]}"
do
	check_linux_packages $linux_package
done

printf "\nChecking for Python packages\n"
for python_package in "${python_packages[@]}"
do
	check_python_packages $python_package
done
