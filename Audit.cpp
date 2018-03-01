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

sqlite3 *Global_Ctx_Database = NULL;
static pthread_rwlock_t Lock_LookupCache_UID = PTHREAD_RWLOCK_INITIALIZER;
static pthread_rwlock_t Lock_LookupCache_UID_ChRoot = PTHREAD_RWLOCK_INITIALIZER;
static std::unordered_map<uint32_t, void *> LookupCache_UID;
static std::unordered_map<uint32_t, std::string> LookupCache_UID_ChRoot;


int AuditedFS::Audit::Init() {
	LogD("AuditFS", "Audit::Init: Initializing audit context\n");

	int rc_testopen = open(Global_Path_Database, O_RDONLY);
	int rc_sqopen;

	sqlite3_stmt *stmtmtmt;

	if (rc_testopen == -1) {
		LogD("AuditFS", "Audit::Init: Database not found, creating\n");
retry_opendb:
		rc_sqopen = sqlite3_open_v2(Global_Path_Database, &Global_Ctx_Database, SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_READWRITE |
										 SQLITE_OPEN_CREATE, NULL);

		if (rc_sqopen != SQLITE_OK) {
			goto retry_opendb;
		}

		auto rc_sqcreatdb = sqlite3_exec(Global_Ctx_Database, "CREATE TABLE audit ("
			"ID INTEGER PRIMARY KEY, "
			"UID INTEGER NOT NULL, "
			"Path TEXT NOT NULL, "
			"Flags INTEGER"
			")", NULL, NULL, NULL);

		if (rc_sqcreatdb != SQLITE_OK)
			goto fatal;


		rc_sqcreatdb = sqlite3_exec(Global_Ctx_Database, "CREATE TABLE chroot ("
			"ID INTEGER PRIMARY KEY, "
			"UID INTEGER NOT NULL UNIQUE, "
			"Path TEXT NOT NULL, "
			"Flags INTEGER"
			")", NULL, NULL, NULL);

		if (rc_sqcreatdb != SQLITE_OK)
			goto fatal;
		else
			goto createdb_finished;


fatal:
		LogE("AuditFS", "Audit::Init: FATAL: Unable to create tables in database %s\n", Global_Path_Database);
		abort();

	}

	LogD("AuditFS", "Audit::Init: Database found\n");

	rc_sqopen = sqlite3_open_v2(Global_Path_Database, &Global_Ctx_Database, SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_READWRITE, NULL);

	if (rc_sqopen != SQLITE_OK) {
		LogE("AuditFS", "Audit::Init: FATAL: Unable to open database %s\n", Global_Path_Database);
		abort();
	}


	pthread_rwlock_wrlock(&Lock_LookupCache_UID);
	assert(sqlite3_prepare_v2(Global_Ctx_Database, "SELECT * FROM audit", -1, &stmtmtmt, NULL) == SQLITE_OK);

	while (SQLITE_ROW == sqlite3_step(stmtmtmt)) {
		int thisuid = sqlite3_column_int(stmtmtmt, 1);
		auto thispath = sqlite3_column_text(stmtmtmt, 2);
		int thisflag = sqlite3_column_int(stmtmtmt, 3);

		auto it = LookupCache_UID.find(thisuid);

		std::map<std::string, int> *thislc2;

		if (it != LookupCache_UID.end())
			thislc2 = (std::map<std::string, int> *)it->second;
		else {
			thislc2 = new std::map<std::string, int>;
			LookupCache_UID.insert(std::pair<uint32_t, void *>(thisuid, thislc2));
		}

		thislc2->insert(std::pair<std::string, int>((const char *)thispath, thisflag));

		LogD("AuditFS", "Audit::Init: Audit Rule: UID %u LC2 %p Flags 0x%08x Path %s\n", thisuid, thislc2, thisflag, thispath);

	}

	sqlite3_finalize(stmtmtmt);

	assert(sqlite3_prepare_v2(Global_Ctx_Database, "SELECT * FROM chroot", -1, &stmtmtmt, NULL) == SQLITE_OK);

	while (SQLITE_ROW == sqlite3_step(stmtmtmt)) {
		int thisuid = sqlite3_column_int(stmtmtmt, 1);
		auto thispath = sqlite3_column_text(stmtmtmt, 2);
//		int thisflag = sqlite3_column_int(stmtmtmt, 3);

		LookupCache_UID_ChRoot[thisuid] = (const char *)thispath;

		LogD("AuditFS", "Audit::Init: Chroot Rule: UID %u Path %s\n", thisuid, thispath);

	}
	pthread_rwlock_unlock(&Lock_LookupCache_UID);



createdb_finished:

	return 0;
}

int AuditedFS::Audit::GetFlags(uint32_t __uid, int __flag, const char *__path, std::string &__chroot_path) {

	int ret = 0;
	std::string pathstr = __path;

	LogD("AuditFS", "Audit::GetFlags: Searching LookupCache_UID_ChRoot for UID %u\n", __uid);

	pthread_rwlock_rdlock(&Lock_LookupCache_UID_ChRoot);
	auto it_chroot = LookupCache_UID_ChRoot.find(__uid);
	if (it_chroot != LookupCache_UID_ChRoot.end()) {
		LogD("AuditFS", "Audit::GetFlags: Found UID %u in LookupCache_UID_ChRoot\n", __uid);
		ret = 3;
		__chroot_path = it_chroot->second;
	}
	pthread_rwlock_unlock(&Lock_LookupCache_UID_ChRoot);


	if (ret)
		return ret;

	LogD("AuditFS", "Audit::GetFlags: Searching LookupCache_UID for UID %u\n", __uid);

	pthread_rwlock_rdlock(&Lock_LookupCache_UID);
	auto it_uid = LookupCache_UID.find(__uid);
	if (it_uid != LookupCache_UID.end()) {
		auto *LookupTable_Path = (std::map<std::string, int> *) it_uid->second;

		for (auto &thisent : *LookupTable_Path) {

			auto rc_find = pathstr.find(thisent.first);

			LogD("AuditFS", "Audit::GetFlags: spath=%s, rpath=%s, flags=0x%08x\n", __path,
			     thisent.first.c_str(), thisent.second);

			if (rc_find != std::string::npos) {
				if (thisent.second & __flag) {
					LogD("AuditFS", "Audit::GetFlags: Found flag %0x08x for path %s in rule %s\n", __flag, __path,
					     thisent.first.c_str());
					ret = 1;
				} else {
					LogD("AuditFS", "Audit::GetFlags: Flag %0x08x NOT found for path %s in rule %s, we're done\n", __flag, __path,
					     thisent.first.c_str());
					ret = 2;
					goto finished;
				}
			}

		}

finished:
		pthread_rwlock_unlock(&Lock_LookupCache_UID);

		return ret;
	}

}