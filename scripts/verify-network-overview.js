// Append to network-overview.js in any JS engine; no browser or router required.
(function(){
 const sample=[{name:'Test 插座',mac:'AA:BB:CC:00:00:01',ips:['192.168.100.17'],cached_ips:['192.168.100.38'],reserved_ip:'',via:['sfp28-3'],state:'seen'},{name:'Archive',mac:'AA:BB:CC:00:00:02',ips:[],cached_ips:[],reserved_ip:'192.168.100.18',via:[],state:'unknown'}];
 const checks={
  caseInsensitive:networkFilter(sample,'aa:bb','seen','').length===1,
  reservedIpSearch:networkFilter(sample,'.18','','').length===1,
  cachedIpSearch:networkFilter(sample,'.38','','').length===1,
  combined:networkFilter(sample,'插座','seen','sfp28-3').length===1,
  emptyMatch:networkFilter(sample,'missing','','').length===0,
  sameNameNotMerged:networkPeerGroups([{name:'Switch',model:'X',ip:'',mac:'A',via:'a',kind:'lldp'},{name:'Switch',model:'X',ip:'',mac:'B',via:'b',kind:'lldp'}]).length===2,
  bondMembersGrouped:networkPeerGroups([{name:'Switch',model:'X',ip:'192.168.100.253',mac:'A',via:'a',kind:'discovered'},{name:'Switch',model:'X',ip:'192.168.100.253',mac:'B',via:'b',kind:'discovered'}])[0].paths.length===2
 };
 if(Object.values(checks).some(x=>!x))throw Error(JSON.stringify(checks));
 return {passed:Object.keys(checks).length,checks};
})()
