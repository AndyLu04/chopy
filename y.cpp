#include <iostream>
#include <fstream>

using namespace std;

int main()
{
	cout << "HW" << endl;
	
	system("cat /opt/apparmor/px/x.cpp");
	
	/*
	fstream file;
	file.open("Reader.txt", ios::out | ios::trunc);
	file.write("abc\n", sizeof("abc\n"));
	file.close(); 
		
	char str[100];		

	/*
	file.open("Reader.txt", ios::in);
	file.read(str,sizeof("abc\n"));
	file.close(); 
	*/
	
	/*
	file.open("g.txt", ios::in);
	file.read(str,sizeof("123"));
	file.close(); 
	
	cout << str << endl;
	*/
	
	return 0;
}
