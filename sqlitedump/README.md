
Tool for dumping sqlite data based on a provided config file. 
Does minimal transformations for timestamps.

#### config file format (json)

~~~json
{
"tables":[
        {
            "name":"tablename", //alias for use with the --t parameter
            "config":
                { 
                    "query":"select id, col1, col2 from downloads_url_chains" , 
                    "fields":
                        [
                            {"name":"id","ord":0,"coltype":"str", "nullable":0},
                            {"name":"col1","ord":1,"coltype":"str", "nullable":0},
                            {"name":"col2_alias","ord":2,"coltype":"str", "nullable":0}
                        ]
                }
        }]
}
~~~


#### usage

~~~bash
sqlitedump -i sample/ActivitiesCache.db -o output1.csv -t ActivitiesCache -c config/win_timeline.json
~~~