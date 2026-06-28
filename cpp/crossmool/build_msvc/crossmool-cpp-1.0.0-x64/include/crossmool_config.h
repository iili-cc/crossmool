#ifndef CROSSMOOL_CONFIG_H
#define CROSSMOOL_CONFIG_H

// DLL export / import control
#ifdef _MSC_VER
  #ifdef CROSSMOOL_BUILD_DLL
    #define CROSSMOOL_API __declspec(dllexport)
  #else
    #ifdef CROSSMOOL_USE_DLL
      #define CROSSMOOL_API __declspec(dllimport)
    #else
      #define CROSSMOOL_API
    #endif
  #endif
#else
  #define CROSSMOOL_API
#endif

#endif // CROSSMOOL_CONFIG_H
