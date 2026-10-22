#pragma once

#include <windows.h>

/*
 * Marker files are the primary evidence channel for every tool in this
 * repository: a self-test is only "passed" when a known byte string appears at
 * a known path. Nothing is inferred from console output alone.
 */

BOOL PexMarkerWrite(PCSTR szDirectory, PCSTR szName, PCSTR szText);
BOOL PexMarkerVerify(PCSTR szDirectory, PCSTR szName, PCSTR szText);
BOOL PexMarkerRemove(PCSTR szDirectory, PCSTR szName);
