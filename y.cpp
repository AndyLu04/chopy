#include <iostream>
#include <fstream.h>

using namespace std;

int main()
{
	cout << "HW" << endl;
	fstream file;
	file.open("Reader.txt", ios::out | ios::trunc);
	file.write("abc\n", sizeof("abc\n"));
	file.close(); 
		
	char str[100];		

	file.open("Reader.txt", ios::in);
	file.read(str,sizeof("abc\n"));
	cout << str << endl;
	
	return 0;
}
