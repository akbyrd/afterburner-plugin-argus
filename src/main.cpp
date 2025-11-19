#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <argus/argus_monitor_data_api.h>
#include <msi/MAHMSharedMemory.h>
#include <msi/MSIAfterburnerMonitoringSourceDesc.h>

using namespace argus_monitor::data_api;

// -------------------------------------------------------------------------------------------------
// Infrastructure

using b8 = bool;
using f32 = float;
using i32 = int;
using u32 = unsigned int;

template <typename TLambda>
struct Defer
{
	const TLambda lambda;

	Defer(TLambda&& l) : lambda(static_cast<TLambda&&>(l)) {}
	~Defer() { lambda(); }
};

struct
{
	template<typename TLambda>
	Defer<TLambda> operator<<(TLambda&& l)
	{
		return Defer<TLambda>(static_cast<TLambda&&>(l));
	}
} make_deferred;

#define DEFER_UNIQUE_NAME2(x, y) x ## y
#define DEFER_UNIQUE_NAME1(x, y) DEFER_UNIQUE_NAME2(x, y)
#define DEFER_UNIQUE_NAME() DEFER_UNIQUE_NAME1(__defer_, __COUNTER__)
#define defer auto DEFER_UNIQUE_NAME() = make_deferred << [&]

// -------------------------------------------------------------------------------------------------
// State

struct ArgusState
{
	b8                      initialized = false;
	HANDLE                  file        = nullptr;
	const ArgusMonitorData* data        = nullptr;
	HANDLE                  dataMutex   = nullptr;
};

struct ThreadState
{
	b8                            poll             = false;
	b8                            dataAvailable    = false;
	u32                           lastCycleCounter = 0;
	HANDLE                        thread           = nullptr;
	const ArgusMonitorSensorData* waterSensor      = nullptr;
};

struct State
{
	ArgusState  argus;
	ThreadState thread;
};

static State state = {};

// -------------------------------------------------------------------------------------------------
// Argus API

static void Argus_Deinit(ArgusState& s);

static b8
Argus_Init(ArgusState& s)
{
	b8 success = false;
	defer { if (!success) Argus_Deinit(s); };

	DWORD flags = FILE_MAP_READ;
	s.file = OpenFileMappingW(flags, FALSE, kMappingName());
	if (!s.file) return false;

	const void* data = MapViewOfFile(s.file, flags, 0, 0, kMappingSize());
	if (!data) return false;
	s.data = static_cast<const ArgusMonitorData*>(data);

	s.dataMutex = OpenMutexW(READ_CONTROL | MUTANT_QUERY_STATE | SYNCHRONIZE, FALSE, kMutexName());
	if (!s.dataMutex) return false;

	s.initialized = true;
	success = true;
	return true;
}

static void
Argus_Deinit(ArgusState& s)
{
	if (s.dataMutex)
		CloseHandle(s.dataMutex);

	if (s.data)
		UnmapViewOfFile(s.data);

	if (s.file)
		CloseHandle(s.file);

	s = {};
}

// -------------------------------------------------------------------------------------------------
// Argus - Afterburner Integration

static DWORD WINAPI Argus_Thread_Update(void* lpParam);
static void Argus_Thread_Deinit(ThreadState& ts, ArgusState& as);

static b8
Argus_Thread_Init(ThreadState& ts, ArgusState& as)
{
	b8 success = false;
	defer { if (!success) Argus_Thread_Deinit(ts, as); };

	ts.poll = true;
	ts.thread = CreateThread(
		nullptr,
		0,
		static_cast<LPTHREAD_START_ROUTINE>(Argus_Thread_Update),
		&state,
		0,
		nullptr
	);
	if (!ts.thread) return false;

	success = true;
	return true;
}

static DWORD WINAPI
Argus_Thread_Update(void* lpParam)
{
	State* s = static_cast<State*>(lpParam);
	ThreadState& ts = s->thread;
	ArgusState& as = s->argus;

	// NOTE: Reading from the poll flag is intentionally unsynchronized. There are no other writes
	// the polling thread depends on.
	while (ts.poll)
	{
		defer { Sleep(250); };

		if (!as.initialized)
			Argus_Init(as);

		// Handle Argus restarting (could change sensor layout)
		ts.dataAvailable &= ts.lastCycleCounter <= as.data->CycleCounter;
		if (!ts.dataAvailable)
		{
			ts.lastCycleCounter = as.data->CycleCounter;
			ts.dataAvailable = as.data->Signature == 0x4D677241;
			if (ts.dataAvailable)
			{
				WaitForSingleObject(as.dataMutex, INFINITE);
				defer { ReleaseMutex(as.dataMutex); };

				i32 sensorTypeIndex = SENSOR_TYPE_TEMPERATURE;
				u32 sensorOffset    = as.data->OffsetForSensorType[sensorTypeIndex];
				u32 sensorCount     = as.data->SensorCount[sensorTypeIndex];

				for (u32 i = 0; i < sensorCount; ++i)
				{
					// NOTE: We assume sensor data never changes layout while Argus is running
					const ArgusMonitorSensorData& sensor = as.data->SensorData[sensorOffset + i];
					if (wcscmp(sensor.Label, L"T Sensor") == 0)
					{
						ts.waterSensor = &sensor;
						break;
					}
				}
			}
		}

		// NOTE: Handling Argus monitor closing or restarting while we are running:
		// * The mapped memory and mutex remain valid because the are global objects and we're holding
		//   handles to them.
		// * Because the data is statically sized / allocated we don't have to worry about any
		//   pointers changing.
		// * The memory is zero filled by Argus during graceful shutdown.
		// * During a crash, the memory is left as-is. We can detect this case by watching for the
		//   CycleCounter freezing, but we dont' currently have a need to do so.
		// * After restarting the sensor layout could have changed and our cached value for the water
		//   sensor may be wrong. We detect this by watching for the CycleCounter jumping backwards to
		//   a lower value.
	}

	return 0;
}

static void
Argus_Thread_Deinit(ThreadState& ts, ArgusState& as)
{
	// NOTE: Writing to the poll flag is intentionally unsynchronized. There are no other writes the
	// polling thread depends on.
	ts.poll = false;
	WaitForSingleObject(ts.thread, INFINITE);
	CloseHandle(ts.thread);
	ts = {};

	Argus_Deinit(as);
}

// -------------------------------------------------------------------------------------------------
// Plugin API

//extern "C" __declspec(dllexport) BOOL
//SetupSource(DWORD dwIndex, HWND hWnd)

//extern "C" __declspec(dllexport) void
//Uninit()

extern "C" __declspec(dllexport) DWORD
GetSourcesNum()
{
	return 1;
}

extern "C" __declspec(dllexport) BOOL
GetSourceDesc(DWORD dwIndex, LPMONITORING_SOURCE_DESC pDesc)
{
	(void) dwIndex;

	// NOTE: Afterburner appears to use the Windows-1252 codepage instead of UTF-8
	*pDesc = MONITORING_SOURCE_DESC {
		.dwVersion       = pDesc->dwVersion,
		.szName          = "T Sensor",
		.szUnits         = "\x{b0}C", // °
		.szFormat        = "%.0f",
		.szGroup         = "MOBO",
		.dwID            = MONITORING_SOURCE_ID_PLUGIN_MOBO,
		.dwInstance      = 0,
		.fltMaxLimit     = 0.0f,
		.fltMinLimit     = 100.0f,
		.szNameTemplate  = {},
		.szGroupTemplate = {},
	};
	return TRUE;
}

extern "C" __declspec(dllexport) FLOAT
GetSourceData(DWORD dwIndex)
{
	(void) dwIndex;

	// NOTE: Reading from the water sensor is intentionally unsynchronized. We can't have a torn
	// read since it lives on a single cache line.
	if (state.thread.waterSensor && state.thread.waterSensor->Value)
		return f32(state.thread.waterSensor->Value);

	// NOTE: FLT_MAX is the "invalid" value. It will cause the sensor to be removed (overlay, tray).
	return 0;
}

// -------------------------------------------------------------------------------------------------
// Windows API

extern "C" BOOL WINAPI
DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	(void) hInstance;
	(void) lpReserved;

	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			if (!Argus_Thread_Init(state.thread, state.argus))
				return FALSE;
			break;

		case DLL_PROCESS_DETACH:
			Argus_Thread_Deinit(state.thread, state.argus);
			break;
	}

	return TRUE;
}

// TODO: Figure out where the plugin description and setup comes from (MFC extension framework thingy?)
// TODO: Argus_Thread_Init/Deinit run on the main thread and Argus_Thread_Update runs on the polling thread. This is confusing.
