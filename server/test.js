
const mongoose = require('./database');
const Protocol = require('./Protocol');
const { ConnectionPoolMonitoringEvent } = require('mongodb');

var info = db.runCommand({
    listCollections: 1,
    filter: { name: "protocols" }
  });
  
  // גישה לאופציות של האוסף
  printjson(info.cursor.firstBatch[0].options);
  
  // גישה להגדרת ה-validator (אם קיימת)
  printjson(info.cursor.firstBatch[0].options.validator);
  