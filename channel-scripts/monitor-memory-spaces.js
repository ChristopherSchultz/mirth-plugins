/*
 * monitor-memory-spaces.js
 *
 * Copyright (C) 2021 Christopher Schultz
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * =================================
 *
 * Allows an HTTP client to request information about JVM memory spaces.
 *
 * Instructions for configuring a channel for this script:
 * 1. Summary
 *    Data Types:
 *      Source Connector: Inbound=XML, Outbound=XML
 *      Return memory info (Destination): Inbound=XML, Outbound=JSON
 *      Message Storage / Pruning: (your choice)
 *
 * 2. Source Connector:
 *    HTTP Listener
 *      Local address: (your choice)
 *      Source Queue: OFF
 *      Response: "Return memory usage" (Destination)
 *      Base Context path: (your choice)
 *      Message Content: XML Body
 *      Parse Multipart: NO
 *      Include Metadata: YES
 *      Response content type: application/json
 *      Response data type: text
 *      Charset Encoding: UTF-8
 *
 * 3. Destination
 *   Return memory usage
 *     Connector Type: JavaScript Writer
 *     Queue settings: Never
 *     Javscript Writer Settings:
 *       JavaScript: (this script you are reading, here)
 *
 *
 * To use this channel, make an HTTP GET request to the interface:port/context-path
 * you chose. This channel will return a JSON response similar to the following:
 * ```
 *  {
 *     "total": 4273471488,
 *     "free": 2454537128,
 *     "max": 4273471488,
 *     "used": 1818934360,
 *     "usedpct": 42.56339056216022,
 *     "usedpctmax": 42.56339056216022,
 *     "heaps" : [
 *        "PS Old Gen": {
 *            "init": 2863661056,
 *            "used": 1465000640,
 *            "committed": 2863661056,
 *            "max": 2863661056,
 *            "usedpct": 51.15831138362207,
 *            "usedpctmax": 51.15831138362207
 *        }
 *     ]
 *  }
 *```
 *
 * The data outside of the "heaps" property are for the systen as a whole;
 * these samples are a summary of the entire "Java heap".
 *
 * The individual items contained within the "heaps" array are individual
 * memory spaces, not just heap spaces (despite the name).
 *
 * The "usedpct" is the total used heap space divided by the total heap space.
 * "usedpctmax" is the total used heap space divided by the MAXIMUM total heap
 * space that the heap may take. For example, if you have specified -Xms1024M
 * and -Xmx4906M then your initial heap size will be ~1GiB and if you are using
 * 500MiB heap, then "usedpct" will be ~50% but "usedpctmax" will be ~12.5%
 * when you initially start Mirth, and gradually "usedpct" will approach
 * "usedpctmax" as the overall heap size grows from its initial allocation
 * towards its maximum. (It's worth noting that, for long-running services, it
 * makes a lot of sense to set -Xms=-Xmx to avoid having to resize the heap
 * at all.)
 *
 * If you specify a /heapname/ at the end of the URL e.g. "interface:port/context-path/PS Old Gen"
 * you will get just the information about that single memory space:
 *
 * ```
 *  {
 *      "init": 2863661056,
 *      "used": 1465590464,
 *      "committed": 2863661056,
 *      "max": 2863661056,
 *      "usedpct": 51.17890823459241,
 *      "usedpctmax": 51.17890823459241
 *  }
 *```
 *
 * If you specify a sample after your heap name, you will get just that data
 * value back e.g. "interface:port/context-path/PS Old Gen/usedpct":
 * ```
 * 51.193783738070984
 * ```
 *
 *
 * If you specify the special heap 'name' "GC:run", this channel will
 * make a call to java.lang.Runtime.gc() and return a successful response:
 *
 *```
 * {"status":"ok","operation":"GC:run"}
 *```
 *
 * There is no guarantee that the JVM will actually perform garbage collection.
 * Please see the javadoc for java.lang.Runtime.gc for more information.
 */
var msg = XML(connectorMessage.getRawData());
// Why exactly do we have to call URLDecoder.decode, here?
var heapName = java.net.URLDecoder.decode(msg['RequestContextPath'], 'UTF-8');
var sampleName = '';

// segments = []/[heapinfo]/[requested-heap]/[samplename]
var segments = heapName.split('/', 10);
if(segments.length > 2) {
  heapName = segments[2];

  if(segments.length > 3) {
    sampleName = segments[3];
  }
} else {
  heapName = '';
}

// JSON object to return
var data;

if('GC:run' == heapName) {
  var runtime = java.lang.Runtime.getRuntime();
  runtime.gc();

  data = {
    "status" : "ok",
    "operation" : "GC:run"
  };
} else if('' != heapName) {
  // Specific heap info
  var memBeans = java.lang.management.ManagementFactory.getMemoryPoolMXBeans();
  if(memBeans && !memBeans.isEmpty()) {
    for(var i=memBeans.iterator(); i.hasNext(); ) {
      var mpBean = i.next();
      if(mpBean.getName() == heapName) {
        var memUsage = mpBean.getUsage();
        data = { "init" : memUsage.getInit(),
                 "used" : used = memUsage.getUsed(),
                 "committed" : total = memUsage.getCommitted(),
                 "max" : max = memUsage.getMax(),
                 "usedpct" : 100.0 * (used / total),
                 "usedpctmax" : 100.0 * (used / max)
               };
      }
    }
    if(data) {
      // Return only the requested sample
      if(sampleName && data.hasOwnProperty(sampleName)) {
        data = data[sampleName];
      }
    }
  } else {
    data = { "error" : "Unknown heap '" + heapName + "'" };
  }
} else {
  var runtime = java.lang.Runtime.getRuntime();

  var total, free, max, used;
  data = { "total" : total = runtime.totalMemory(),
           "free" : free = runtime.freeMemory(),
           "max" : max = runtime.maxMemory(),
           "used" : (total - free),
           "usedpct" : 100.0 * ((total - free) / total),
           "usedpctmax" : 100.0 * ((max - free) / max),
           "heaps" : {}
  };

  var memBeans = java.lang.management.ManagementFactory.getMemoryPoolMXBeans();
  if(memBeans && !memBeans.isEmpty()) {
    for(var i=memBeans.iterator(); i.hasNext(); ) {
      var mpBean = i.next();
//    logger.debug('Found heap MBean \'' + mpBean.getName() + '\': ' + mpBean + " with type " + mpBean.getType());
      if (true || 'Heap memory' == mpBean.getType().toString()) {
        var memUsage = mpBean.getUsage();
        var heapInfo = { "init" : memUsage.getInit(),
                         "used" : used = memUsage.getUsed(),
                         "committed" : total = memUsage.getCommitted(),
                         "max" : max = memUsage.getMax(),
                         "usedpct" : 100.0 * (used / total),
                         "usedpctmax" : 100.0 * (used / max)
                       };
        data['heaps'][mpBean.getName()] = heapInfo;
      } else {
        logger.debug('Ignoring non-heap memory pool ' + mpBean.getName() + ' of type ' + mpBean.getType());
      }
    }
  }
}

return Packages.com.mirth.connect.server.userutil.ResponseFactory.getSentResponse(JSON.stringify(data));

