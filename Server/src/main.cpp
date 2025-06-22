#include "ui.h"
#include "communicator.h"
#include "logger.h"
#include "error.h"
int main(int argc, char* argv[])
{
    UI interface (argc,argv);
    communicator server (interface.get_port(),interface.get_log_loc());
    server.work();
    return 0;
}
