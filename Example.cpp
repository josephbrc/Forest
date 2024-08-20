#include <iostream>
#include "Forest.h"

int main()
{

	if (!Forest::Init()) {
		return 0;
	}

	printf("Process Base: %p\n", Forest::GetFirstModule());

}
