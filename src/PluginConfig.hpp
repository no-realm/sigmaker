#ifndef PLUGINCONFIG_HPP
#define PLUGINCONFIG_HPP

#define MAKE_PLUGIN_VERSION(maj, min, rev)  ((maj << 16) | (min << 8) | rev)
#define PLUGIN_TEXTUAL_VERSION  "v1.0"
#define PLUGIN_VERSION          MAKE_PLUGIN_VERSION(1, 0, 0)

#define PLUGIN_NAME             "SigMaker"

#endif
