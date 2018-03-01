/*
    This file is part of AuditedFS.
    Copyright (C) 2017-2018  ReimuNotMoe <reimuhatesfdt@gmail.com>

    AuditedFS is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    AuditedFS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AuditedFS.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "AuditedFS.hpp"

using namespace Reimu;

using System::Environment::CommandLineParser;

char *Global_Path_SrcPath = NULL;
char *Global_Path_APISocket = NULL;
char *Global_Path_Database = NULL;

int main(int argc, char *argv[])
{
	umask(0);

	CommandLineParser clp(argc, argv);

	char *arg_src_path = clp.OptArg("s");
	char *arg_dest_path = clp.OptArg("d");
	char *arg_api_socket_path = clp.OptArg("a");
	char *arg_database_path = clp.OptArg("b");

	if (!arg_dest_path || !arg_src_path || !arg_api_socket_path || !arg_database_path) {
		LogE("AuditedFS", "main: Please specify the source path (-s), destination path (-d), database path (-b), and API socket path (-a).\n");
		exit(1);
	}

	LogI("AuditedFS", "main: Source path: %s\n", arg_src_path);
	LogI("AuditedFS", "main: Destination path: %s\n", arg_dest_path);
	LogI("AuditedFS", "main: Database path: %s\n", arg_database_path);
	LogI("AuditedFS", "main: API socket path: %s\n", arg_api_socket_path);

	Global_Path_SrcPath = arg_src_path;
	Global_Path_APISocket = arg_api_socket_path;
	Global_Path_Database = arg_database_path;


	AuditedFS::Audit::Init();

	char *argv_fuse[] = { "auditedfs", "-f", arg_dest_path };

	fuse_operations xmp_oper = AuditedFS::FuseOperations::GetOperations();

	LogD("AuditedFS","main: xmp_oper at %p\n", &xmp_oper);
	LogD("AuditedFS","main: calling fuse_main\n");

	int ret = fuse_main(3, argv_fuse, &xmp_oper, NULL);

	return ret;
}

